package main

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/busoc/panda"
	"github.com/midbel/cli"
)

var replay = &cli.Command{
	Desc: `
Replay read TM/PP packets from a file created with the capture command
and send them to the given multicast address.

options:
  -c count  simulate lost of count packets
  -f file   read packets from file
  -h        print this message and exit
  -l loop   send all packets loop times
  -n        dry run
  -r rate   increase transmission rate of packets
  -v        diagnostics on stdout
`,
	Short: "replay captured packets",
	Alias: []string{"re"},
	Usage: "replay [-v] [-f] [-c] [-d] [-l] [-r] [-z] [-n] <host:port>",
	Run:   runReplay,
}

func runReplay(cmd *cli.Command, args []string) error {
	file := cmd.Flag.String("f", filepath.Join(os.TempDir(), "capture.dat"), "file")
	count := cmd.Flag.Int("c", 0, "count")
	loop := cmd.Flag.Int("l", 0, "loop")
	rate := cmd.Flag.Int("r", 1, "rate")
	dry := cmd.Flag.Bool("n", false, "dry")
	verbose := cmd.Flag.Bool("v", false, "verbose")

	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	log.SetPrefix("[replay] ")
	if !*verbose {
		log.SetOutput(ioutil.Discard)
	}
	var (
		r   io.ReadCloser
		w   io.Writer
		err error
	)
	if r, err = forward(*file, *loop, *rate); err != nil {
		return err
	}
	defer r.Close()

	if !*dry {
		w, err = Dial(cmd.Flag.Arg(0), *count)
		if err != nil {
			return err
		}
	} else {
		w = ioutil.Discard
	}
	_, err = io.Copy(w, r)
	return err
}

type item struct {
	Elapsed time.Duration
	Packet  []byte
}

func decodeItem(bs []byte) (int, mud.Packet, error) {
	e := binary.BigEndian.Uint64(bs[:8])
	i := &item{
		Elapsed: time.Duration(e),
		Packet:  bs[8:],
	}
	return len(bs), i, nil
}

func (i *item) Payload() []byte {
	bs := make([]byte, len(i.Packet))
	copy(bs, i.Packet)
	return bs
}

func (i *item) Bytes() ([]byte, error) {
	return i.Payload(), nil
}

func (i *item) Timestamp() time.Time {
	return time.Now()
}

type forwarder struct {
	*mud.Reader
	file *os.File

	limit int
	count int
	rate  time.Duration
}

func forward(file string, count, rate int) (io.ReadCloser, error) {
	if rate == 0 {
		rate = 1
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	return &forwarder{
		Reader: mud.NewReader(scan(f), mud.DecoderFunc(decodeItem)),
		file:   f,
		limit:  count,
		rate:   time.Duration(rate),
	}, nil
}

func (f *forwarder) Read(bs []byte) (int, error) {
	p, err := f.Reader.Read()
	switch err {
	case nil:
		i, _ := p.(*item)
		if f.rate > 0 {
			<-time.After(i.Elapsed / f.rate)
		} else {
			<-time.After(i.Elapsed * -f.rate)
		}
		log.Printf("write: %d, elapsed: %s, sum: %x", len(i.Packet), i.Elapsed, md5.Sum(i.Packet))
		return copy(bs, i.Payload()), nil
	case mud.ErrDone:
		f.Reader.Close()
		f.file.Close()
		if f.count += 1; f.limit > 0 && f.count >= f.limit {
			return 0, errDone
		}

		if f.file, err = os.Open(f.file.Name()); err != nil {
			return 0, err
		}
		f.Reader = mud.NewReader(scan(f.file), mud.DecoderFunc(decodeItem))
		return f.Read(bs)
	default:
		return 0, err
	}
}

type scanner struct {
	*bufio.Scanner
}

func scan(r io.Reader) io.Reader {
	s := bufio.NewScanner(r)
	s.Split(func(bs []byte, ateof bool) (int, []byte, error) {
		if len(bs) < 2 {
			return 0, nil, nil
		}
		n := int(binary.BigEndian.Uint16(bs[:2])) + 2
		if len(bs) < n {
			return 0, nil, nil
		}
		vs := make([]byte, n-2)
		copy(vs, bs[2:n])
		return n, vs, nil
	})
	return &scanner{s}
}

func (s *scanner) Read(bs []byte) (int, error) {
	if s.Scan() {
		return copy(bs, s.Bytes()), nil
	}
	err := s.Err()
	if err != nil {
		return 0, err
	}
	return 0, io.EOF
}

type conn struct {
	net.Conn

	limit int
	count int
	curr  int

	writer io.Writer
}

func Dial(addr string, limit int) (net.Conn, error) {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}

	var count int
	if limit > 0 {
		count = rand.Intn(limit)
	}
	return &conn{
		Conn:   c,
		limit:  limit,
		count:  count,
		writer: c,
	}, nil
}

func (c *conn) Write(bs []byte) (int, error) {
	if c.curr += 1; c.limit > 0 && c.curr >= c.count {
		if c.writer == ioutil.Discard {
			c.writer = c.Conn
		} else {
			c.writer = ioutil.Discard
		}
		c.curr, c.count = 0, rand.Intn(c.limit)
	}
	return c.writer.Write(bs)
}
