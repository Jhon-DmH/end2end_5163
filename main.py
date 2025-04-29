import tkinter as tk
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from client.login import LoginWindow

def main():
    root = tk.Tk()
    app = LoginWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()