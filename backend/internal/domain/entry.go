package domain

type DirEntry struct {
	ParentIno int64  `json:"parent_ino"`
	Name      string `json:"name"`
	ChildIno  int64  `json:"child_ino"`
	Mode      uint32 `json:"mode"`
}
