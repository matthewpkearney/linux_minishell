#Matt Kearney
#I pledge my honor that I have abided by the Stevens Honor System.
FLAGS = -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -g

all: minishell.c
	gcc $(FLAGS) minishell.c -o minishell

clean:
	rm minishell
	@echo "Cleaned."