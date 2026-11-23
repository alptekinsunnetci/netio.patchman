package rollout

import (
	"reflect"
	"testing"

	"netio.patchman/internal/store"
)

func TestPlanBatches(t *testing.T) {
	h := []int64{1, 2, 3, 4, 5, 6, 7}
	if got := PlanBatches(h, 1, 3); !reflect.DeepEqual(got, [][]int64{{1}, {2, 3, 4}, {5, 6, 7}}) {
		t.Errorf("canary 1, batch 3: %v", got)
	}
	if got := PlanBatches(h, 0, 0); !reflect.DeepEqual(got, [][]int64{{1, 2, 3, 4, 5, 6, 7}}) {
		t.Errorf("one stage: %v", got)
	}
	if got := PlanBatches(h, 10, 2); !reflect.DeepEqual(got, [][]int64{{1, 2, 3, 4, 5, 6, 7}}) {
		t.Errorf("canary larger than the fleet: %v", got)
	}
	if got := PlanBatches(nil, 1, 2); len(got) != 0 {
		t.Errorf("no hosts: %v", got)
	}
}

func TestPlanGroups(t *testing.T) {
	got := PlanGroups([][]int64{{1, 2, 3}, {3, 4}, {5}}, 1)
	if !reflect.DeepEqual(got, [][]int64{{1}, {2, 3}, {4}, {5}}) {
		t.Errorf("groups: %v", got)
	}
	if got := PlanGroups([][]int64{{1}, {1}}, 0); !reflect.DeepEqual(got, [][]int64{{1}}) {
		t.Errorf("duplicate host: %v", got)
	}
}

func TestSortHosts(t *testing.T) {
	hosts := []store.Host{{ID: 1, Hostname: "c", SecurityScore: 50}, {ID: 2, Hostname: "a", SecurityScore: -1}, {ID: 3, Hostname: "b", SecurityScore: 90}}
	SortHosts(hosts, OrderScoreDesc)
	if hosts[0].ID != 3 || hosts[1].ID != 1 || hosts[2].ID != 2 {
		t.Errorf("score desc: %+v", hosts)
	}
	SortHosts(hosts, OrderScoreAsc)
	if hosts[0].ID != 1 || hosts[2].ID != 2 {
		t.Errorf("score asc: %+v", hosts)
	}
	SortHosts(hosts, OrderHostname)
	if hosts[0].Hostname != "a" || hosts[2].Hostname != "c" {
		t.Errorf("hostname: %+v", hosts)
	}
}
