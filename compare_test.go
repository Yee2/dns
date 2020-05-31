package main

import "testing"

func TestCompare(t *testing.T) {
	type args struct {
		parent string
		child  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{

		{name: "1", args: args{"a.a", "a.a"}, want: true},
		{name: "2", args: args{"a.a", "a.a."}, want: true},
		{name: "3", args: args{"a.a.", "a.a"}, want: true},
		{name: "4", args: args{"a.a.", "a.a."}, want: true},
		{name: "5", args: args{"abc.*", "a.a"}, want: false},
		{name: "6", args: args{"abc.aa", "*.aa"}, want: false},
		{name: "7", args: args{"abd.com", "abc.com"}, want: false},
		{name: "7", args: args{"a.**.com", "ab.c.com"}, want: false},
		{name: "7", args: args{"**.com", ".com"}, want: false},
		{name: "7", args: args{"**.com", "a.b.c.d.com"}, want: true},
		{name: "8", args: args{"abc.com", "abc.dom"}, want: false},
		{name: "9", args: args{"www.*.com", "www.abc.com"}, want: true},
		{name: "10", args: args{"www.*.com", ".www.abc.com"}, want: false},
		{name: "11", args: args{".www.*.com", "www.abc.com"}, want: false},
		{name: "12", args: args{".www.*.com", ".www.abc.com"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Compare(tt.args.parent, tt.args.child); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
