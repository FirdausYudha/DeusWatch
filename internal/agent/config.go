package agent

// Config adalah desired-state pengumpulan yang dikelola manager (config push,
// design doc bagian 12). Version dinaikkan tiap perubahan agar agent tahu kapan
// harus menerapkan ulang.
type Config struct {
	Version int      `json:"version"`
	Sources []Source `json:"sources"`
}
