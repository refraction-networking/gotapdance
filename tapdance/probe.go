package tapdance

import (
  "context"
  pb "github.com/sergeyfrolov/gotapdance/protobuf"
)

func ProbeDecoy(ip string, sni string) (err error) {
  flow, _ := makeTdFlow(flowBidirectional, nil)

  flow.tdRaw.decoySpec = *pb.InitTLSDecoySpec(ip, sni)
  flow.tdRaw.pinDecoySpec = true

  err = flow.tdRaw.tryDialOnce(context.Background(), pb.S2C_Transition_S2C_SESSION_INIT)
  _ = flow.tdRaw.Close()
  return
}
