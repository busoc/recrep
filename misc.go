package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	random "math/rand"
	"net"
	"os"
	"time"

	"github.com/busoc/panda"
	"github.com/midbel/cli"
)

const (
	tm = "%9d | %s | %6d | %12s | %4d | %6d | %9d | %-16s | % x"
	pp = "%9d | %s | %-12s | %x | %-12s | %6d | %5d | %-24x | %-v"
)

var sim = &cli.Command{
	Usage: "simulate [-c] [-s] <host:port>",
	Short: "generate random tm/pp packets",
	Alias: []string{"sim", "alea"},
	Run:   runSimulate,
}

var list = &cli.Command{
	Usage: "list [-k] [-w] [-c] [-s] <file>",
	Short: "list catpured packets",
	Alias: []string{"ls"},
	Run:   runList,
}

func runSimulate(cmd *cli.Command, args []string) error {
	count := cmd.Flag.Int("c", 0, "count")
	size := cmd.Flag.Int("s", 512, "size")
	every := cmd.Flag.Duration("e", time.Second, "every")
	extra := cmd.Flag.Bool("x", false, "extra")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	c, err := net.Dial("udp", cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer c.Close()

	r := rand.Reader
	if *extra {
		r = io.TeeReader(r, hex.Dumper(os.Stderr))
	}
	random.Seed(time.Now().Unix())
	if *size < 1 {
		*size = random.Intn(512)
	}
	for i := 0; ; i++ {
		<-time.After(*every)
		if *count > 0 && i >= *count {
			break
		}
		i := random.Intn(*size)
		if _, err := io.CopyN(c, r, int64(i)); err != nil {
			return err
		}
	}
	return nil
}

func runList(cmd *cli.Command, args []string) error {
	file := cmd.Flag.String("w", "", "write packets list to file")
	kind := cmd.Flag.String("k", "", "packets type")
	cumul := cmd.Flag.Bool("c", false, "cumulative time")
	sum := cmd.Flag.Bool("s", false, "packet checksum")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	f, err := os.Open(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()

	if w, err := os.Create(*file); err == nil {
		log.SetOutput(w)
		defer w.Close()
	} else {
		log.SetOutput(os.Stdout)
	}

	switch *kind {
	case "tm":
		return showPackets(f, panda.DecodeTM(), 10)
	case "pp":
		return showPackets(f, panda.DecodePP(), 12)
	case "", "raw":
		return showItems(f, *sum, *cumul)
	default:
		return fmt.Errorf("unsupported packets type %q", *kind)
	}
}

func showPackets(r io.Reader, d panda.Decoder, skip int) error {
	rs := panda.NewReader(scan(r), panda.DecoderFunc(decodeItem))

	var count uint32
	for {
		i, err := rs.Read()
		switch err {
		case nil:
		case panda.ErrDone:
			return nil
		default:
			return err
		}
		p, err := decodePacket(i, d, skip)
		if err != nil {
			return err
		}

		count++
		switch p := p.(type) {
		case panda.Telemetry:
			ds := p.Data
			if len(ds) >= 4 {
				ds = p.Data[:4]
			}
			c, e := p.CCSDSHeader, p.ESAHeader
			log.Printf(tm,
				count,
				e.Timestamp().Format("2006-01-02T15:04:05.000Z"),
				c.Sequence(),
				c.SegmentationFlag(),
				c.Apid(),
				c.Len(),
				e.Sid,
				e.PacketType(),
				ds,
			)
		case panda.Parameter:
			u := p.UMIHeader
			log.Printf(pp,
				count,
				u.Timestamp().Format("2006-01-02T15:04:05.000Z"),
				u.State,
				u.Code,
				u.Type,
				u.Unit,
				u.Length,
				p.Data,
				p.Value(),
			)
		default:
			continue
		}
	}
	return nil
}

func showItems(r io.Reader, sum, cumul bool) error {
	rs := panda.NewReader(scan(r), panda.DecoderFunc(decodeItem))

	var (
		count, size uint64
		duration    time.Duration
	)
	for {
		p, err := rs.Read()
		switch err {
		case nil:
		case panda.ErrDone:
			log.Printf("%d packets (%fKB) %s\n", count, float64(size)/1024, duration)
			return nil
		default:
			return err
		}
		i, ok := p.(*item)
		if !ok {
			continue
		}
		count++
		size += uint64(len(i.Packet))
		duration += i.Elapsed

		var (
			kind string
			num  uint16
		)
		switch p := i.Packet[0]; p {
		default:
			continue
		case panda.TagTM:
			kind, num = "tm", 1
		case panda.TagPP:
			kind, num = "pp", binary.BigEndian.Uint16(i.Packet[10:12])
		}
		e := i.Elapsed
		if cumul {
			e = duration
		}
		var s []byte
		if sum {
			is := md5.Sum(i.Packet)
			s = is[:]
		}
		t := time.Unix(int64(binary.BigEndian.Uint32(i.Packet[1:5])), 0).Format(time.RFC3339)
		log.Printf("%5d | %3s | %4d | %24s | %s | %4d | %x\n", count, kind, num, e, t, len(i.Packet), s)
	}
}

func decodePacket(p panda.Packet, d panda.Decoder, s int) (panda.Packet, error) {
	i, ok := p.(*item)
	if !ok {
		return nil, fmt.Errorf("invalid packet type")
	}
	_, v, err := d.Decode(i.Payload()[s:])
	return v, err
}
