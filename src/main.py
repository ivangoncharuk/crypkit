import click
from rich.console import Console
from rich.panel import Panel
from InquirerPy import prompt

console = Console()


@click.group()
def cli():
    """Cryptography Toolkit CLI Application"""
    pass


@cli.command()
def menu():
    """Display the main menu using InquirerPy"""
    console.print(Panel("", title="Main Menu", title_align="right"))
    questions = [
        {
            "type": "list",
            "name": "menu_choice",
            "message": "Please select an option:",
            "choices": [
                "Key Generation",
                "File Encryption/Decryption",
                "Steganography",
                "Secure File Shredder",
            ],
        }
    ]
    answers = prompt(questions)
    process_choice(answers["menu_choice"])


def process_choice(choice):
    if choice == 'Key Generation':
        pass # TODO  key_generation_menu()
    elif choice == "File Encryption/Decryption":
        # Call file encryption module
        pass
    elif choice == "Steganography":
        # Call steganography module
        pass
    elif choice == "Secure File Shredder":
        # Call file shredder module
        pass
    else:
        console.print("[bold red]Invalid choice, please try again.[/bold red]")


if __name__ == "__main__":
    cli()
