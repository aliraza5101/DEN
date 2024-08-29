import argparse

class NimGame:
    def __init__(self, num_red, num_blue, version='standard', first_player='computer'):
        self.num_red = num_red
        self.num_blue = num_blue
        self.version = version
        self.current_player = first_player

    def is_game_over(self):
        return self.num_red == 0 or self.num_blue == 0

    def calculate_score(self):
        return self.num_red * 2 + self.num_blue * 3

    def human_move(self):
        valid_move = False
        while not valid_move:
            try:
                move = input("Enter your move (e.g., '1 red' or '2 blue'): ").strip().split()
                if len(move) != 2:
                    raise ValueError("Invalid move format.")
                count, color = int(move[0]), move[1].lower()
                if color not in ['red', 'blue'] or count <= 0 or (color == 'red' and count > self.num_red) or (color == 'blue' and count > self.num_blue):
                    raise ValueError("Invalid move values.")
                valid_move = True
            except (ValueError, IndexError) as e:
                print(f"Invalid move: {e}. Try again.")

        if color == 'red':
            self.num_red -= count
        else:
            self.num_blue -= count

    def computer_move(self):
        possible_moves = self.get_possible_moves()
        best_move = possible_moves[0]  # Currently, just pick the first move in the list
        print(f"Computer chooses to remove {best_move[0]} {best_move[1]}")
        if best_move[1] == 'red':
            self.num_red -= best_move[0]
        else:
            self.num_blue -= best_move[0]

    def get_possible_moves(self):
        moves = []
        if self.num_red >= 2:
            moves.append((2, 'red'))
        if self.num_blue >= 2:
            moves.append((2, 'blue'))
        if self.num_red >= 1:
            moves.append((1, 'red'))
        if self.num_blue >= 1:
            moves.append((1, 'blue'))
        return moves

    def play_game(self):
        while not self.is_game_over():
            print(f"Red Marbles: {self.num_red}, Blue Marbles: {self.num_blue}")
            if self.current_player == 'human':
                self.human_move()
                self.current_player = 'computer'
            else:
                self.computer_move()
                self.current_player = 'human'

        print("Game over!")
        print(f"Final score: {self.calculate_score()}")

def main():
    parser = argparse.ArgumentParser(description="Play the Red-Blue Nim Game.")
    parser.add_argument("num_red", type=int, nargs='?', default=10, help="Number of red marbles")
    parser.add_argument("num_blue", type=int, nargs='?', default=10, help="Number of blue marbles")
    parser.add_argument("--version", type=str, choices=['standard', 'misere'], default='standard', help="Game version (standard or misere)")
    parser.add_argument("--first-player", type=str, choices=['human', 'computer'], default='computer', help="First player (human or computer)")

    args = parser.parse_args()

    game = NimGame(args.num_red, args.num_blue, args.version, args.first_player)
    game.play_game()

if __name__ == "__main__":
    main()