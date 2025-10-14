import click
import pathlib
import subprocess
import sys
import yaml


@click.group()
@click.pass_context
@click.option("-n", "--name", required=True, help="Service name")
def cli(context: click.Context, name: str) -> None:
    context.ensure_object(dict)
    # Load settings from settings.yml and store to click's context
    with SETTINGS_PATH.open() as f:
        context.obj["settings"] = yaml.safe_load(f)
    # Store arguments to click's context
    context.obj["name"] = name


@cli.command("start")
@click.pass_context
def start_get_flag(context: click.Context) -> None:
    """Run the get-flag script for a specific service"""
    name = context.obj["name"]
    get_flag_script = GET_FLAG_PATH / f"{name}.py"
    if not get_flag_script.is_file():
        click.echo(click.style(f"get-flag for {name} doesn't exist", fg="red"))
        sys.exit(1)
    command = f"nohup python3 {get_flag_script.as_posix()} & 2>/dev/null"
    process = subprocess.run(command, stdout=subprocess.DEVNULL, shell=True)
    if process.returncode != 0:
        click.echo(click.style(f"get-flag for {name} failed", fg="red"))
        sys.exit(1)
    click.echo(click.style(f"get-flag for {name} started", fg="green"))


@cli.command("stop")
@click.pass_context
def stop_get_flag(context: click.Context) -> None:
    """Stop the get-flag script for a specific service"""
    name = context.obj["name"]
    get_flag_script = GET_FLAG_PATH / f"{name}.py"
    command_args= [
        "pkill -SIGTERM -f",
        f"\"python3 {get_flag_script.as_posix()}\""
    ]
    command = " ".join(command_args)
    process = subprocess.run(command, stdout=subprocess.DEVNULL, shell=True)
    if (process.returncode != 0) and (process.returncode != -15):
        click.echo(click.style("Invalid command", fg="red"))
    else:
        click.echo(click.style(f"Stopped: {command}", fg="yellow"))


@cli.command("status")
@click.pass_context
def status_get_flag(context: click.Context) -> None:
    """Get status of get-flag script"""
    name = context.obj["name"]
    get_flag_script = GET_FLAG_PATH / f"{name}.py"
    command_args = [
        "ps -ef |",
        f"grep \"python3 {get_flag_script.as_posix()}\" |",
        "grep -v \"grep\""
    ]
    command = " ".join(command_args)
    process = subprocess.run(command, stdout=subprocess.DEVNULL, shell=True)
    if process.returncode != 0:
        click.echo(click.style("Not running", fg="yellow"))
    else:
        click.echo(click.style("Running", fg="green"))


if __name__ == "__main__":
    BASE_DIR = pathlib.Path(__file__).parent.resolve()
    SETTINGS_PATH = BASE_DIR / "settings.yml"
    GET_FLAG_PATH = BASE_DIR / "get_flag"
    cli()
