package iputil

import (
	"fmt"
	"testing"
)

func TestCheckIPInCidrRange(t *testing.T) {
	res := IpCidrContains("192.168.2.3", "192.168.1.1/22")
	fmt.Println(res)
}
