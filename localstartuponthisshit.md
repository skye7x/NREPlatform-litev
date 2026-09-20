mkdir -p /root/.ssh
chmod 700 /root/.ssh

cat > /root/.ssh/authorized_keys <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINulaAB/6qgw/SDlbaV4Vv22PvkGOfXa04j3nOp0HmW0 bartek@skyportal.pl
EOF

chmod 600 /root/.ssh/authorized_keys
chown -R root:root /root/.ssh

/etc/init.d/sshd restart 2>/dev/null || true

exit 0