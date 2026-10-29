"""A tiny demo program to obfuscate."""


def greet(name):
    secret = "the answer is 42"
    return f"Hello, {name}! ({secret})"


def add(a, b):
    return a + b


if __name__ == "__main__":
    print(greet("world"))
    print("2 + 3 =", add(2, 3))
