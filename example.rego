package example

# Define a rule to deny access by default if no matching rule is found
default allow = false

rules := data.access_control_rules

# Define a rule to check if a user is allowed to access a resource based on their role
allow {
    some i
    input.path == rules[i].path
    input.roles[_] == rules[i].roles[_]
}

allow {
    some i
    input.path == rules[i].path
    count(rules[i].roles) == 0
}
