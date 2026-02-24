# Key, IV and Mode retrieved from the binary
echo "Printing the flag!"
openssl enc -d -aes-256-cbc -in ./vault/flag.enc  \
-K a0fbf7e40d943e056fe586fd7906ca82552c16b8565013e936946e6c67593628 \
-iv 9e6e4ac1382c8708926cd8c9fafc1dda


# ----------- The other files for my curiosity -----------------

# echo "Printing the password list"
# openssl enc -d -aes-256-cbc -in ./vault/password_list.enc  \
# -K a0fbf7e40d943e056fe586fd7906ca82552c16b8565013e936946e6c67593628 \
# -iv 9e6e4ac1382c8708926cd8c9fafc1dda


# echo "Printing the logs"
# openssl enc -d -aes-256-cbc -in ./vault/secret_messages.enc  \
# -K a0fbf7e40d943e056fe586fd7906ca82552c16b8565013e936946e6c67593628 \
# -iv 9e6e4ac1382c8708926cd8c9fafc1dda
