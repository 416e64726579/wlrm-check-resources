package helpers

import (
	"bufio"
	"net/url"
	"os"
	"sort"
)

// IsValidURL tests a string to determine if it is a well-structured url or not.
func IsValidURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

// ReadDomainsFile reads a slice of domains from a localfile
func ReadDomainsFile(domainsFile *string, domains *[]string) error {

	file, err := os.Open(*domainsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	comment1 := []rune(`#`)
	comment2 := []rune(`/`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if char := []rune(scanner.Text()); (char[0] != comment1[0]) || (char[0] != comment2[0] && char[1] != comment2[0]) {
			if IsValidURL(string(char)) {
				*domains = append(*domains, string(char))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// DifferenceSlices finds difference between two slices
func DifferenceSlices(iterated []string, itering []string) []string {
	var diffStr []string
	for _, el := range iterated {
		in, out := func(slice []string, val string) (bool, string) {
			i := sort.Search(len(slice), func(i int) bool { return slice[i] >= val })
			if i < len(slice) && slice[i] == val {
				return false, ""
			}
			return true, val
		}(itering, el)
		if in {
			diffStr = append(diffStr, out)
		}
	}
	return diffStr
}

// Contains returns true if a string exists in a slice
func Contains(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func unique(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// RemoveDuplicate returns slice without duplicates and values which were duplicated
func RemoveDuplicate(strSlice []string) []string {
	var duplicates []string
	keys := make(map[string]bool)
	slice := []string{}
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			slice = append(slice, entry)
		} else {
			duplicates = append(duplicates, entry)
		}
	}
	duplicates = unique(duplicates)
	slice = DifferenceSlices(slice, duplicates)
	return slice
}
