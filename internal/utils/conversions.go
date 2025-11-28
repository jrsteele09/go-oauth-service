package utils

func ToStringSlice(slice []any) []string {
	stringSlice := make([]string, 0)
	for _, v := range slice {
		if s, ok := v.(string); ok {
			stringSlice = append(stringSlice, s)
		}
	}
	return stringSlice
}
