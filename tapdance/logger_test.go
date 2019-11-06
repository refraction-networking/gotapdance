package tapdance

import (
	"testing"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestStatsReporting(t *testing.T) {
	reg := ConjureReg{}
	testRTT := uint32(1000)
	reg.stats = &pb.SessionStats{
		TotalTimeToConnect: &testRTT,
		TcpToDecoy:         &testRTT,
	}
	StatsReporting(reg.stats)
}
