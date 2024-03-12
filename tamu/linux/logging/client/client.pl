#!/usr/bin/env perl
use strict;
use warnings;
use IO::Socket::INET;
use POSIX "strftime";

# Change this to the IP of the server
my $server_ip = "127.0.0.1";
my $server_port = 46515;

# See what's sent and monitored at the bottom of the script

# Handle SIGINT
my @child_processes;
sub stop_child_processes {
    kill 'INT', @child_processes;
}
$SIG{'INT'} = 'stop_child_processes';


# Register client with server
my ($hostname) = ns_system('./busybox', 'hostname');
my ($clientName, $clientKey) = register($hostname);


# ------------------------------------------------------------------------------

sub print_log {
    my @lines = @_;
    my $timestamp = strftime "%Y-%m-%d %H:%M:%S", localtime;
    print "[$timestamp] ", @lines, "\n";
    return;
}

# Run commands without calling the shell
sub ns_system {
    my ($command, @arguments) = @_;
    my $pid = open(my $fh_child, "-|");
    if (!$pid) {
        exec { $command } $command, @arguments;
        exit;
    }
    push @child_processes, $pid;
    my @output = <$fh_child>;
    close $fh_child;
    return @output;
}
sub ns_systemFH {
    my ($command, @arguments) = @_;
    my $pid = open(my $fh_child, "-|");
    if (!$pid) {
        exec { $command } $command, @arguments;
        exit;
    } 
    push @child_processes, $pid;
    return $fh_child;
}

sub get_files_recursively {
    my @dirs = @_;
    my @files = ns_system('./busybox', 'find', @dirs, '-type', 'f');
    map { chomp $_ } @files;
    return @files;
}

sub connect_to_server {
    my ($port) = @_;
    $port = $server_port if (!defined $port);
    my $socket = IO::Socket::INET->new(
      PeerAddr => $server_ip,
      PeerPort => $port,
      Proto    => 'tcp'
    );
    my $wait = 1;
    while ((! $socket) && $wait < 16) {
        sleep $wait;
        $wait *= 2;
    }
    if ($wait >= 16) {
        die "Failed to connect to $server_ip:$port : $!";
    }
    $socket->autoflush(1);
    return $socket;
}

sub register {
    my ($hostname) = @_;
    my $socket = connect_to_server;
    $socket->send("register\n");
    $socket->send("$hostname\n");

    # Wait for connection to be established, try up to 5 times
    my $response;
    foreach (1..5) {
        sleep $_;
        $socket->recv($response, 80);
        last if ($response =~ m/Key/);
    }
    (my $clientName, my $clientKey) = $response =~ m/Name: (client_[a-zA-Z]+_\d+)\nKey: (\d+)\n/;

    if (defined $clientName && defined $clientKey) {
        print_log "Register: success";
    } else {
        print_log "Register: failure";
    }
    $socket->close();
    return ($clientName, $clientKey);
}

sub login {
    my $socket = connect_to_server;

    # Wait for connection to be established, try up to 5 times
    my $response;
    $socket->send("login\n");
    $socket->send("$clientName\n");
    $socket->send("$clientKey\n");
    foreach (1..5) {
        sleep $_;
        $socket->recv($response, 80);
        last if ($response =~ m/Auth/);
    }

    if ($response =~ m/Auth success/) {
        print_log "Login: success";
    } elsif ($response =~ m/Auth failure/) {
        print_log "Login: failure";
    }
    return $socket;
}

sub send_info {
    my $socket = login($clientName, $clientKey);

    my $info = join "", ns_system('./busybox',  'sh', '-c', 'hostname; date; uname -a; cat /etc/os-release; lspci; lsusb; ifconfig');

    $socket->send("info\n");
    $socket->send($info);
    $socket->send("⟃---EOF---⟄\n");
    return;
}

sub send_log {
    my ($file) = @_;
    my $pid = fork;
    if ($pid) {
        push @child_processes, $pid;
        select(undef, undef, undef, 0.2); # Sleep for fraction of second
        return;
    }

    # Check that log exists and is readable by current user
    exit if (! -e $file || ! -r _);

    my $socket = login($clientName, $clientKey);

    # Replace / character with similar-looking character that is valid
    # for filenames. Used to show full path to file
    my $fileName = $file =~ s/\//／/gr;

    # Upload tailed log continuously
    $socket->send("log\n");
    $socket->send("$fileName\n");
    print_log "Log: Uploading $file";
    my $tailLog = ns_systemFH('./busybox', './busybox', 'tail', '-F', "$file");
    while (<$tailLog>) {
        $socket->send($_);
    }
    print_log "Log: Closing $file";
    close($tailLog);
    $socket->send("⟃---EOF---⟄\n");
    exit;
}

sub send_processes {
    my $pid = fork;
    if ($pid) {
        push @child_processes, $pid;
        return;
    }

    my $socket = login($clientName, $clientKey);

    # Upload process log continuously
    $socket->send("processes\n");
    print_log "Processes: Started";
    my $commandLog = ns_systemFH('./pspy64');
    while (<$commandLog>) {
        $socket->send($_);
    }
    print_log "Processes: Finished";
    close($commandLog);
    $socket->send("⟃---EOF---⟄\n");
    exit;
}

sub send_command_output {
    my ($name, @command) = @_;
    my $pid = fork;
    if ($pid) {
        push @child_processes, $pid;
        return;
    }

    my $socket = login($clientName, $clientKey);

    # Upload command output continously with provided filename
    my ($fileName) = $name;
    $socket->send("command\n");
    $socket->send("$fileName\n");
    print_log "Command: Started @command";
    my $commandLog = ns_systemFH(@command);
    while (<$commandLog>) {
        $socket->send($_);
    }
    print_log "Command: Completed @command";
    close($commandLog);
    $socket->send("⟃---EOF---⟄\n");
    exit;
}

sub send_file {
    my ($file) = @_;
    my $pid = fork;
    if ($pid) {
        push @child_processes, $pid;
        select(undef, undef, undef, 0.2); # Sleep for fraction of second
        return;
    }

    # Check that log exists and is readable by current user
    exit if (! -e $file || ! -r _);

    # Replace / character with similar-looking character that is valid
    # for filenames. Used to show full path to file
    my $fileName = $file =~ s/\//／/gr;
    my ($fileHash) = ns_system('./busybox', 'md5sum', "$file");
    chomp $fileName; chomp $fileHash;
    ($fileHash) = $fileHash =~ m/([0-9a-f]+)/;

    my $socket = login($clientName, $clientKey);

    # Send filename and hash to server, wait for a response with the port to
    # upload the file to
    $socket->send("file\n");
    $socket->send("$fileName\n");
    $socket->send("$fileHash\n");
    $socket->recv(my $ignored, 128);
    my $port = undef;
    my $r;
    my $sleeptime = 2;
    my $attemptcount = 0;
    while (! defined $port) {
        sleep $sleeptime;
        $sleeptime *= 2;
        $sleeptime = 10 if ($sleeptime > 10);
        $socket->recv($r, 128);
        ($port) = $r =~ m/(\d+)/;
        $attemptcount += 1;
        if ($attemptcount >= 5) {
            print_log "File: upload failure ($file)";
            exit;
        }
    }

    # Send file once
    print_log "File: upload port is $port ($file)";
    open(my $fileFH, '<', "$file") || die "Failed to open $file";
    my $fileSocket = connect_to_server $port;
    while (<$fileFH>) {
        $fileSocket->send($_);
    }
    close($fileFH);
    close($fileSocket);

    # Server checks that the uploaded hash matches and informs on error
    # No retry is attempted on failed upload
    $socket->recv(my $response, 128);
    if ($response =~ m/Transfer success/) {
        print_log "File: upload success ($file)";
    } else {
        print_log "File: upload failure ($file)";
    }
    exit;
}

sub watch_directory {
    my ($dir) = @_;
    my $pid = fork;
    if ($pid) {
        push @child_processes, $pid;
        return;
    }

    # Recursively monitor directory for files that are written to. Uploads files when found
    my $monitor = ns_systemFH('./inotifywait', '-r', '-m', '-e', 'close_write', '--format', '%w%f', $dir);
    while (<$monitor>) {
        chomp;
        print "Watch found: $_\n";
        send_file($_);
    }
    exit;
}


send_info();
send_processes();

# ------------------------------------------------------------------------------
# Files, logs, and commands to send to the server

# These files will have their contents sent as they are updated
send_log('/var/log/secure');
send_log('/var/log/auth.log');
send_log('/var/log/audit/audit.log');
send_log('/var/log/cron');
send_log('/var/log/sudo.log');
send_log('/var/log/messages');
send_log('/var/log/syslog');

send_log('/var/log/aide/aide.log');

send_log('/var/log/httpd/access_log');
send_log('/var/log/httpd/error_log');
send_log('/var/log/apache2/access_log');
send_log('/var/log/apache2/error_log');

send_log('/var/log/usbguard/usbguard-audit.log');

my @send_as_files;
foreach my $logfile (get_files_recursively('/var/log')) {
    # Only continuously monitor a log if it looks like a text file, otherwise
    # upload as a single file since sending output line-by-line may corrupt
    # files that aren't append-only
    if ((-T $logfile && $logfile !~ m"/var/log/sudo-io/") || ($logfile =~ m"/var/log/(httpd|apache2)") {
        send_log($logfile);
    } else {
        push @send_as_files, $logfile;
    }
}

# These files will be sent once
send_file('/etc/crontab');         # Scheduled jobs
send_file('/etc/group');           # Group list
send_file('/etc/hosts');           # IP -> hostnames
send_file('/etc/hosts.allow');     # Allowed hosts
send_file('/etc/hosts.deny');      # Denied hosts
send_file('/etc/inetd.conf');      # Internet service daemon configuration
send_file('/etc/logrotate.conf');  # Control log rotation
send_file('/etc/passwd');          # User list
send_file('/etc/securetty');       # TTY's allowing root login
#send_file('/etc/shadow');          # User passwords
send_file('/etc/sudoers');         # Users who can run commands as another user (including root)
send_file('/etc/sysctl.conf');     # Kernel options
send_file('/etc/syslog.conf');     # Syslog configuration
send_file('/var/log/lastlog');     # Previously logged in users
send_file('/var/log/wmtp');        # Current logged in users

foreach my $file (get_files_recursively('/etc/pam.d'),
                  get_files_recursively('/etc/rc/init.d'),
                  #get_files_recursively('/etc/ssh'),
                  #get_files_recursively('/etc/security'),
                  get_files_recursively('/etc/sysconfig'),
                  get_files_recursively('/etc/cron*'),
                  get_files_recursively('/etc/init.d'),
                  @send_as_files) {
    send_file($file);
}

# These commands will have their output sent as they are updated
#send_command_output('journalctl', 'journalctl', '-f');
#send_command_output('busybox', 'sh', '-c', 'tail -F /var/log/audit/audit.log | ausearch -l --format text --start today');
# Had some issues specifying timezone when parsing the output, so setting it here
send_command_output('busybox', 'sh', '-c', 'TZ=America/Chicago tail -F /var/log/audit/audit.log | ausearch -l --format text --start today');

# These directories and their subdirectories will be watched and any new/modified files will be sent
watch_directory('/tmp');
watch_directory('/dev/shm');
watch_directory('/home');
watch_directory('/etc');

# ------------------------------------------------------------------------------

# Wait for processes to exit. Do not remove
foreach (@child_processes) {
    waitpid $_, 0;
}
