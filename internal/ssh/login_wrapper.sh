#!/bin/bash
# Login wrapper script

echo -n "login: "
read username

if [ -z "$username" ]; then
    exit 0
fi

echo -n "Password: "
read -s password
echo

# Call Go binary to authenticate
/usr/local/bin/ssh-server-auth "$username" "$password"
exit_code=$?

if [ $exit_code -eq 0 ]; then
    # Authentication successful
    # The Go binary will have set environment variables
    source /tmp/ssh_session_$$.env 2>/dev/null
    
    # Start user shell
    if [ -n "$USER_CHROOT" ] && [ -n "$USER_NETNS" ]; then
        exec ip netns exec "$USER_NETNS" /usr/sbin/chroot "$USER_CHROOT" /bin/bash -l
    fi
fi

echo "Login failed"
exit 1
