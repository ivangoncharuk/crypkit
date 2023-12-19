import click
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from InquirerPy import prompt
from key_generation import key_generation_menu

console = Console()


def display_intro():
    """
    Display the introduction with the application name and author credits.
    """
    intro_text = "Cryptography Toolkit\nMade by Ivan Goncharuk"
    console.print(Panel(intro_text, expand=False, border_style="blue"))


@click.group()
def cli():
    """
    Cryptography Toolkit CLI Application
    """
    display_intro()


@cli.command()
def menu():
    """
    Display the main menu using InquirerPy with enhanced Rich styling.
    """
    menu_items = {
        "key_gen": "🔑 Key Generation",
        "file_enc_dec": "🔒 File Encryption/Decryption",
        "steganography": "🎨 Steganography",
        "file_shredder": "🗑️  Secure File Shredder",
    }

    questions = [
        {
            "type": "list",
            "name": "menu_choice",
            "message": "Select:",
            "choices": list(menu_items.values()),
        }
    ]
    answers = prompt(questions)

    # Find the key corresponding to the selected value
    choice_key = next(
        key for key, value in menu_items.items() if value == answers["menu_choice"]
    )
    process_choice(choice_key)


def process_choice(choice):
    """
    Process the user's choice and call the appropriate module function.
    """
    if choice == "key_gen":
        key_generation_menu()
    elif choice == "file_enc_dec":
        # Call file encryption module
        pass
    elif choice == "steganography":
        # Call steganography module
        pass
    elif choice == "file_shredder":
        # Call file shredder module
        pass
    else:
        console.print(Markdown("🚨 **Invalid choice, please try again.**"))


if __name__ == "__main__":
    cli()
