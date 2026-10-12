use std::io::{self, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

pub fn parse_shell(value: &str) -> Option<Shell> {
    match value.to_ascii_lowercase().as_str() {
        "bash" => Some(Shell::Bash),
        "zsh" => Some(Shell::Zsh),
        "fish" => Some(Shell::Fish),
        "powershell" | "pwsh" => Some(Shell::PowerShell),
        _ => None,
    }
}

pub fn generate_completion(shell: Shell, stdout: &mut dyn Write) -> io::Result<()> {
    match shell {
        Shell::Bash => stdout.write_all(BASH_COMPLETION.as_bytes()),
        Shell::Zsh => stdout.write_all(ZSH_COMPLETION.as_bytes()),
        Shell::Fish => stdout.write_all(FISH_COMPLETION.as_bytes()),
        Shell::PowerShell => stdout.write_all(POWERSHELL_COMPLETION.as_bytes()),
    }
}

const BASH_COMPLETION: &str = r#"# bash completion for dioramactl
_dioramactl() {
    local cur prev words cword
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion -n = || return
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local commands="check completion config d2k download help install kubeconfig reset uninstall upgrade version"

    case "${prev}" in
        dioramactl)
            COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
            return 0
            ;;
        completion)
            COMPREPLY=($(compgen -W "bash zsh fish powershell" -- "${cur}"))
            return 0
            ;;
        help)
            COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
            return 0
            ;;
        config)
            COMPREPLY=($(compgen -W "get set edit path" -- "${cur}"))
            return 0
            ;;
        kubeconfig)
            COMPREPLY=($(compgen -W "fetch merge view" -- "${cur}"))
            return 0
            ;;
        d2k)
            COMPREPLY=($(compgen -W "fetch install" -- "${cur}"))
            return 0
            ;;
        download)
            COMPREPLY=($(compgen -W "--arch --bin-url --custom-url --glibc --help --musl --offline --path --proxy --temp-dir --version" -- "${cur}"))
            return 0
            ;;
        check)
            COMPREPLY=($(compgen -W "--help --install-prereqs --pprof-server" -- "${cur}"))
            return 0
            ;;
        install)
            COMPREPLY=($(compgen -W "--apiserver-extra-sans --cpu-manager-policy --cpu-manager-policy-options --d2k --d2k-namespace --debug --help --image --install-prereqs --local-storage --mtu --name --node-ip --offline-install --path --portainer-edge-async --portainer-edge-id --portainer-edge-image --portainer-edge-key --pprof-server --proxy --reserved-cpus --run-mode --system-reserved --version" -- "${cur}"))
            return 0
            ;;
        *)
            ;;
    esac

    if [[ "${cur}" == -* ]]; then
        case "${words[1]}" in
            download)
                COMPREPLY=($(compgen -W "--arch --bin-url --custom-url --glibc --help --musl --offline --path --proxy --temp-dir --version" -- "${cur}"))
                ;;
            check)
                COMPREPLY=($(compgen -W "--help --install-prereqs --pprof-server" -- "${cur}"))
                ;;
            install)
                COMPREPLY=($(compgen -W "--apiserver-extra-sans --cpu-manager-policy --cpu-manager-policy-options --d2k --d2k-namespace --debug --help --image --install-prereqs --local-storage --mtu --name --node-ip --offline-install --path --portainer-edge-async --portainer-edge-id --portainer-edge-image --portainer-edge-key --pprof-server --proxy --reserved-cpus --run-mode --system-reserved --version" -- "${cur}"))
                ;;
            *)
                COMPREPLY=($(compgen -W "--help" -- "${cur}"))
                ;;
        esac
        return 0
    fi

    COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
}
complete -F _dioramactl dioramactl
"#;

const ZSH_COMPLETION: &str = r#"#compdef dioramactl

_dioramactl() {
    local -a commands
    commands=(
        'check:Check host prerequisites'
        'completion:Generate shell completion scripts'
        'config:Manage diorama configuration'
        'd2k:Manage Docker-to-Kubernetes (d2k) API translator'
        'download:Download the binary bundle for offline installation'
        'help:Help about any command'
        'install:Install diorama and configure the system service'
        'kubeconfig:Manage kubeconfig context and cluster access'
        'reset:Reset cluster data and restart services'
        'uninstall:Uninstall diorama and remove associated system resources'
        'upgrade:Upgrade diorama to a different version'
        'version:Print version information'
    )

    _arguments -C \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'dioramactl commands' commands
            ;;
        args)
            # The *:: action above rebases words to the normal arguments.
            case $words[1] in
                completion)
                    _values 'shells' 'bash' 'zsh' 'fish' 'powershell'
                    ;;
                download)
                    _arguments \
                        '--arch[Target architecture]' \
                        '--bin-url[Custom URL for binary download]' \
                        '--custom-url[Custom URL for binary download]' \
                        '--glibc[Use glibc-based binary]' \
                        '--help[Help for download]' \
                        '--musl[Use musl-based binary]' \
                        '--offline[Download offline bundle]' \
                        '--path[Directory to download files into]' \
                        '--proxy[HTTP/HTTPS proxy URL]' \
                        '--temp-dir[Temporary directory]' \
                        '--version[Version to download]'
                    ;;
                check)
                    _arguments \
                        '--help[Help for check]' \
                        '--install-prereqs[Install missing prerequisites]' \
                        '--pprof-server[Include pprof port]'
                    ;;
            esac
            ;;
    esac
}

_dioramactl "$@"
"#;

const FISH_COMPLETION: &str = r#"# fish completion for dioramactl
complete -c dioramactl -f
complete -c dioramactl -n "__fish_use_subcommand" -a check -d "Check host prerequisites"
complete -c dioramactl -n "__fish_use_subcommand" -a completion -d "Generate shell completion scripts"
complete -c dioramactl -n "__fish_use_subcommand" -a config -d "Manage diorama configuration"
complete -c dioramactl -n "__fish_use_subcommand" -a d2k -d "Manage Docker-to-Kubernetes (d2k) API translator"
complete -c dioramactl -n "__fish_use_subcommand" -a download -d "Download the binary bundle for offline installation"
complete -c dioramactl -n "__fish_use_subcommand" -a help -d "Help about any command"
complete -c dioramactl -n "__fish_use_subcommand" -a install -d "Install diorama and configure the system service"
complete -c dioramactl -n "__fish_use_subcommand" -a kubeconfig -d "Manage kubeconfig context and cluster access"
complete -c dioramactl -n "__fish_use_subcommand" -a reset -d "Reset cluster data and restart services"
complete -c dioramactl -n "__fish_use_subcommand" -a uninstall -d "Uninstall diorama and remove associated system resources"
complete -c dioramactl -n "__fish_use_subcommand" -a upgrade -d "Upgrade diorama to a different version"
complete -c dioramactl -n "__fish_use_subcommand" -a version -d "Print version information"

complete -c dioramactl -n "__fish_seen_subcommand_from completion" -a "bash zsh fish powershell"

complete -c dioramactl -n "__fish_seen_subcommand_from download" -l arch -d "Target architecture"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l bin-url -d "Custom URL for binary download"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l custom-url -d "Custom URL for binary download"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l glibc -d "Use glibc-based binary"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l help -s h -d "Help for download"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l musl -d "Use musl-based binary"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l offline -d "Download offline bundle"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l path -d "Directory to download files into"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l proxy -d "HTTP/HTTPS proxy URL"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l temp-dir -d "Temporary directory"
complete -c dioramactl -n "__fish_seen_subcommand_from download" -l version -d "Version to download"
"#;

const POWERSHELL_COMPLETION: &str = r#"Register-ArgumentCompleter -Native -CommandName dioramactl -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $commands = @('check', 'completion', 'config', 'd2k', 'download', 'help', 'install', 'kubeconfig', 'reset', 'uninstall', 'upgrade', 'version')
    $elements = $commandAst.CommandElements
    $candidates = if ($elements.Count -ge 2 -and $elements[1].Value -eq 'completion' -and $cursorPosition -gt $elements[1].Extent.EndOffset) {
        @('bash', 'zsh', 'fish', 'powershell')
    } elseif ($elements.Count -le 2) {
        $commands
    } else {
        @()
    }
    $candidates | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
"#;
