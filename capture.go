package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/cli"
)

var capture = &cli.Command{
	Desc: `
Capture subscribe to a multicast address and write telemetry packets into
the given file.

options:
  -c count     capture up to count packets
	-d duration  write file(s) with packets covering the given duration
  -i ifi       network interface
  -f file      write captured packets to file
  -h           print this message and exit
  -s size      capture up to size bytes into given file
  -n           dry run
  -v           diagnostics on stdout
  -x           prints packets on stdout like hexdump -C -v
	`,
	Short: "record packets from a multicast stream",
	Alias: []string{"ca"},
	Usage: "capture [-f] [-d] [-c] [-i] [-s] [-n] [-v] [-x] <host:port>",
	Run:   runCapture,
}

func runCapture(cmd *cli.Command, args []string) error {
	file := cmd.Flag.String("f", filepath.Join(os.TempDir(), "capture.dat"), "file")
	ifi := cmd.Flag.String("i", "any", "interface")
	duration := cmd.Flag.Duration("d", 0, "duration")
	count := cmd.Flag.Int("c", 0, "count")
	size := cmd.Flag.Int("s", 0, "size")
	dry := cmd.Flag.Bool("n", false, "dry")
	verbose := cmd.Flag.Bool("v", false, "verbose")

	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	log.SetPrefix("[capture] ")
	if !*verbose {
		log.SetOutput(ioutil.Discard)
	}
	var (
		r   io.Reader
		w   io.Writer
		err error
	)
	if r, err = subscribe(cmd.Flag.Arg(0), *ifi, *duration); err != nil {
		return err
	}
	if c, ok := r.(io.Closer); ok {
		defer c.Close()
	}
	if !*dry {
		w, err = bufferize(*file, uint32(*count), uint32(*size))
		if err != nil {
			return err
		}
	} else {
		w = ioutil.Discard
	}
	if c, ok := w.(io.Closer); ok {
		defer c.Close()
	}
	_, err = io.Copy(w, r)
	return err
}

type buffer struct {
	io.WriteCloser

	limit uint32
	count uint32

	size    uint32
	written uint32
}

func bufferize(file string, c, s uint32) (io.WriteCloser, error) {
	f, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return &buffer{WriteCloser: f, count: c, size: s}, nil
}

func (b *buffer) Write(bs []byte) (int, error) {
	w, err := b.WriteCloser.Write(bs)
	if err != nil {
		return w, err
	}
	if b.written += uint32(len(bs)); b.size > 0 && b.written >= b.size {
		return 0, errDone
	}
	if b.limit += 1; b.count > 0 && b.limit > b.count {
		err = errDone
	}
	return len(bs), err
}

type subscriber struct {
	net.Conn
	queue <-chan []byte
}

func (s *subscriber) Read(bs []byte) (int, error) {
	vs, ok := <-s.queue
	if !ok {
		return 0, errDone
	}
	return copy(bs, vs), nil
}

func subscribe(s, i string, e time.Duration) (net.Conn, error) {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	var ifi *net.Interface
	if i, err := net.InterfaceByName(i); err == nil {
		ifi = i
	}
	c, err := net.ListenMulticastUDP("udp", ifi, a)
	if err != nil {
		return nil, err
	}
	q := make(chan []byte, 100)
	go read(c, e, q)

	return &subscriber{c, q}, nil
}

func read(c net.Conn, e time.Duration, q chan<- []byte) {
	defer close(q)

	var first, last time.Time
	for {
		if !first.IsZero() && time.Since(first) >= e && e > 0 {
			return
		}
		bs := make([]byte, 4096*4)
		n, err := c.Read(bs)
		if n := time.Now(); last.IsZero() {
			first, last = n, n
			continue
		}
		if d := time.Since(last); n > 0 {
			log.Printf("read %d, elapsed: %s, sum: %x", n, d, md5.Sum(bs[:n]))

			e := uint64(d)
			w := new(bytes.Buffer)
			binary.Write(w, binary.BigEndian, uint16(n+binary.Size(e)))
			binary.Write(w, binary.BigEndian, e)
			w.Write(bs[:n])

			q <- w.Bytes()
		}
		last = time.Now()
		if err := abort(err); err != nil {
			return
		}
	}
}

func abort(err error) error {
	if err == nil {
		return err
	}
	if err, ok := err.(net.Error); ok && !err.Temporary() {
		return err
	}
	return err
}
