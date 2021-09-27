package utils

// SplitByLength returns split string by length.
func SplitByLength(str string, length int) []string {
	num := len(str) / length
	if len(str)%length != 0 {
		num++
	}
	arr := make([]string, 0, num)
	for idx := 0; idx < num; idx++ {
		startOffset := idx * length
		endOffset := (idx + 1) * length
		if endOffset > len(str) {
			endOffset = len(str)
		}
		splitStr := str[startOffset:endOffset]
		arr = append(arr, splitStr)
	}
	return arr
}
