# Baby Reversing Level 5
Level was easy to do and i wrote a small script to reverse the order of characters, almost absolutely pointless but here it is...

```py
INPUT = input("Enter a 5 characters license : ")

for i in range(2):
	first_char = INPUT[i]
	eax = 4
	last_char = INPUT[eax-i]
	STRING = list(INPUT)
	STRING[i] = last_char
	STRING[eax-i] = first_char
	print("".join(STRING))
	INPUT = STRING

print(STRING)

```