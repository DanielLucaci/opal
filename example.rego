package example

default allow = false

rules := data.access_control_rules

allow {
    some i
    input.path == rules[i].path
    input.method == rules[i].methods[_]
    input.roles[_] == rules[i].roles[_]
}

allow {
    some i
    input.path == rules[i].path
    input.method == rules[i].methods[_]
    count(rules[i].roles) == 0
}
