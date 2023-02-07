package tritonhttp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Server struct {
	// Addr specifies the TCP address for the server to listen on,
	// in the form "host:port". It shall be passed to net.Listen()
	// during ListenAndServe().
	Addr string // e.g. ":0"

	// VirtualHosts contains a mapping from host name to the docRoot path
	// (i.e. the path to the directory to serve static files from) for
	// all virtual hosts that this server supports
	VirtualHosts map[string]string
}

// ListenAndServe listens on the TCP network address s.Addr and then
// handles requests on incoming connections.
func (s *Server) ListenAndServe() error {

	// Hint: Validate all docRoots
	err := ValidateSetup(s.VirtualHosts)
	if err != nil {
		fmt.Println("Error in validation : ", err.Error())
	}

	fmt.Println("Validation Complete, all docroots look good!")

	// Hint: create your listen socket and spawn off goroutines per incoming client
	ln, err := net.Listen("tcp", s.Addr)

	if err != nil {
		return err
	}

	fmt.Println("Listening on", ln.Addr())

	defer func() {
		err = ln.Close()
		if err != nil {
			fmt.Println("error in closing listener", err)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		fmt.Println("accepted connection", conn.RemoteAddr())
		go s.handleConnection(conn)
	}

}

func ValidateSetup(Directory map[string]string) error {

	for hostname, docRoot := range Directory {
		fmt.Println("Validating for ", hostname, " ", docRoot)
		fi, err := os.Stat(docRoot)

		if os.IsNotExist(err) {
			return err
		}

		if !fi.IsDir() {
			return fmt.Errorf("doc root %q is not a directory", docRoot)
		}

	}
	return nil
}

func (s *Server) handleConnection(conn net.Conn) {
	br := bufio.NewReader(conn)

	for {

		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			fmt.Printf("Failed to set timeout for connection %v \n", conn)
			_ = conn.Close()
			return
		}
		req, err := ReadRequest(br)

		if errors.Is(err, io.EOF) {
			fmt.Printf("Connection closed by %v \n", conn.RemoteAddr())
			_ = conn.Close()
			return
		}

		if err, ok := err.(net.Error); ok && err.Timeout() {
			fmt.Printf("Connection to %v timed out", conn.RemoteAddr())
			// Sending 400
			if req.Method != "" {
				res := &Response{}
				res.send_static_400()
				err2 := res.Write(conn)
				if err2 != nil {
					fmt.Println(err)
				}
			}

			_ = conn.Close()
			return
		}

		if err != nil {
			fmt.Printf("Handle bad request for error , sending 404: %v", err)
			res := &Response{}
			res.send_static_400()
			err = res.Write(conn)
			if err != nil {
				fmt.Println(err)
			}
			_ = conn.Close()
			return
		}

		if !strings.HasPrefix(req.URL, "/") {
			res := &Response{}
			res.send_static_400()
			err = res.Write(conn)
			if err != nil {
				fmt.Println(err)
			}
			_ = conn.Close()
			return
		}

		// Handle good request
		fmt.Printf("Correct request : %v", req)

		// Correct the address
		if req.URL[len(req.URL)-1:] == "/" {
			req.URL += "index.html"
		}

		var file_loc string
		if req.Host == "" {
			fmt.Println("Host in request empty")
			res := &Response{}
			res.send_static_400()
			err = res.Write(conn)
			if err != nil {
				fmt.Println(err)
			}
			_ = conn.Close()
			return
		}
		temp, ok := s.VirtualHosts[req.Host]
		if ok {
			file_loc = temp + req.URL
		} else {
			// Sending 400
			fmt.Println("Host not present - return 404")
			res := &Response{}
			res.send_static_404()
			err2 := res.Write(conn)
			if err2 != nil {
				fmt.Println(err)
			}

			continue
		}

		fileInfo, err := os.Stat(file_loc)
		if err != nil {
			if os.IsNotExist(err) {
				log.Println("File doesnt exists ")
				res := &Response{}
				res.send_static_404()
				err = res.Write(conn)
				if err != nil {
					fmt.Println(err)
				}
				_ = conn.Close()
				return
			}
			fmt.Println("NOP Cant load file , some error occured ", err.Error())
		}
		if fileInfo.IsDir() {
			file_loc += "/index.html"
		}
		_, err = os.Stat(file_loc)
		if err != nil {
			if os.IsNotExist(err) {
				log.Println("File doesnt exists ")
				res := &Response{}
				res.send_static_404()
				err = res.Write(conn)
				if err != nil {
					fmt.Println(err)
				}
				_ = conn.Close()
				return
			}

			fmt.Println("NOP Cant load file , some error occured ", err.Error())
		}
		cleaned_path := filepath.Clean(file_loc)
		if strings.Contains(cleaned_path, s.VirtualHosts[req.Host]) {
			// 200 response
			res := &Response{}
			res.send_static(file_loc, req.Close)
			err = res.Write(conn)
			if err != nil {
				fmt.Println(err)
			}
			if req.Close == true {
				_ = conn.Close()
				return
			}
		} else {

			// 404 - Unauthorised access
			fmt.Println("UnAuthorised access")
			res := &Response{}
			res.send_static_404()
			err = res.Write(conn)
			if err != nil {
				fmt.Println(err)
			}
			continue
		}

	}
}

func (res *Response) send_static_400() {
	res.Proto = "HTTP/1.1"
	res.StatusCode = 400
	res.StatusText = "Bad Request"
	var tmp = map[string]string{
		CanonicalHeaderKey("Date"):       string(FormatTime(time.Now())),
		CanonicalHeaderKey("Connection"): "close",
	}
	res.Headers = tmp
}

func (res *Response) send_static_404() {
	res.Proto = "HTTP/1.1"
	res.StatusCode = 404
	res.StatusText = "Not Found"
	var tmp = map[string]string{
		CanonicalHeaderKey("Date"): string(FormatTime(time.Now())),
	}
	res.Headers = tmp
}

func (res *Response) send_static(url string, close bool) {
	res.FilePath = url
	fileInfo, err := os.Stat(res.FilePath)
	if err != nil {
		fmt.Println("Cant load file")
	}
	data, err := ioutil.ReadFile(res.FilePath)
	if err != nil {
		fmt.Println("File reading error", err)
		return
	}

	res.Proto = "HTTP/1.1"
	res.StatusCode = 200
	res.StatusText = "OK"
	res.Request = nil
	var tmp = map[string]string{
		CanonicalHeaderKey("Content-Type"):   MIMETypeByExtension(filepath.Ext(res.FilePath)),
		CanonicalHeaderKey("Content-Length"): fmt.Sprintf("%v", len(data)),
		CanonicalHeaderKey("Last-Modified"):  string(FormatTime(fileInfo.ModTime())),
		CanonicalHeaderKey("Date"):           string(FormatTime(time.Now())),
	}
	if close == true {
		tmp[CanonicalHeaderKey("Connection")] = "close"
	}
	res.Headers = tmp
	res.OptionalBody = data
}

func (res *Response) Write(w io.Writer) error {
	bw := bufio.NewWriter(w)

	statusLine1 := fmt.Sprintf("%v %v %v\r\n", res.Proto, res.StatusCode, res.StatusText)
	statusLine2 := ""

	keys := make([]string, 0, len(res.Headers))

	for k := range res.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i := 0; i < len(keys); i++ {
		statusLine2 += fmt.Sprintf("%v: %v\r\n", keys[i], res.Headers[keys[i]])
	}
	statusLine2 += "\r\n"
	statusLine := statusLine1 + statusLine2 + string(res.OptionalBody)
	if _, err := bw.WriteString(statusLine); err != nil {
		return err
	}

	if err := bw.Flush(); err != nil {
		return err
	}
	return nil
}

func ReadRequest(br *bufio.Reader) (req *Request, err error) {
	req = &Request{}

	// Read start line
	line, err := ReadLine(br)
	if err != nil {
		return nil, err
	}

	req.Headers = make(map[string]string)
	req.Method, err = parseRequestLine(line, 0)
	if err != nil {
		fmt.Println("Error in Parsing header : ", err.Error())
		return nil, badStringError("malformed start line", line)
	}
	req.Close = false
	req.Proto, err = parseRequestLine(line, 2)
	if err != nil {
		fmt.Println("Error in Parsing header :", err.Error())
		return nil, badStringError("malformed start line", line)
	}
	if req.Proto != "HTTP/1.1" {
		return nil, badStringError("Bad protocol ", line)
	}
	req.URL, err = parseRequestLine(line, 1)
	if err != nil {
		fmt.Println("Error in Parsing header : ", err.Error())
		return nil, badStringError("malformed start line", line)
	}

	if !validMethod(req.Method) {
		return nil, badStringError("invalid method", req.Method)
	}

	for {
		line, err := ReadLine(br)
		if err != nil {
			return nil, err
		}
		if line == "" {
			break
		}
		splitLine := strings.SplitN(line, ":", -1)

		if len(splitLine) != 2 {
			fmt.Println("Header not in format key : val", splitLine)
			return req, fmt.Errorf("something went wrong... return 404")
		}

		for i := 0; i < len(splitLine); i++ {
			splitLine[i] = strings.Trim(splitLine[i], " ")
		}

		if splitLine[0] == "Host" {
			req.Host = splitLine[1]
		} else if splitLine[0] == "Connection" && splitLine[1] == "close" {
			req.Close = true
		}

		ky := splitLine[0]
		vl := splitLine[1]
		req.Headers[ky] = vl

	}
	return req, nil
}

func parseRequestLine(line string, idx int) (string, error) {
	fields := strings.SplitN(line, " ", -1)
	if len(fields) != 3 {
		return "", fmt.Errorf("could not parse the request line, got fields %v", fields)
	}
	return strings.Trim(fields[idx], " "), nil
}

func validMethod(method string) bool {
	return method == "GET"
}

func badStringError(what, val string) error {
	fmt.Println("BadStringError : ", what, val)
	return fmt.Errorf("%s %q", what, val)
}

func ReadLine(br *bufio.Reader) (string, error) {
	var line string
	for {
		s, err := br.ReadString('\n')
		line += s
		if err != nil {
			return line, err
		}
		if strings.HasSuffix(line, "\r\n") {
			line = line[:len(line)-2]
			return line, nil
		}
	}
}
