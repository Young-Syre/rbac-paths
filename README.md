# rbac-paths

[![tests](https://github.com/Young-Syre/rbac-paths/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/rbac-paths/actions/workflows/tests.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![licence](https://img.shields.io/badge/licence-MIT-green)](LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)

An offline Kubernetes RBAC privilege-escalation path finder. It reads a local
`kubectl get ... -o json` dump, builds the subject → permission → escalation
graph, and prints every path from a subject to cluster-admin, shortest first,
with the rule that permits each hop and the action a tester would take.

It never contacts an API server. There is no Kubernetes client in the
dependency tree, because there are no dependencies at all.

## RBAC is additive, and there is no deny

Kubernetes RBAC has two properties that together make it hard to reason about.

It is **purely additive**. There is no deny rule. A subject's permissions are
the union of every rule in every Role and ClusterRole reachable through every
binding that names it or names a group it is in. Nothing anywhere can subtract
from that union, so you cannot look at one object and know what it allows; you
can only look at all of them and add up.

And the permissions it grants are **not the capabilities they imply**. RBAC
authorises a verb on a resource. It does not authorise what that verb lets you
become. `create pods` in a namespace is not "may start a container": a pod spec
names the ServiceAccount whose token is projected into it, and RBAC has no
concept of which service accounts a subject may mount. So `create pods` in a
namespace is, exactly, the union of the permissions of every ServiceAccount in
that namespace. `patch deployments` is the same thing one reconcile later,
because a Deployment is a pod template plus a controller that will act on it.
`create serviceaccounts/token` returns a bearer token. `get secrets` is every
credential in reach. `escalate` and `bind` switch off the permission-containment
check that otherwise stops you granting a permission you do not hold.
`impersonate` on groups reaches `system:masters`, which the API server allows
unconditionally and which no RBAC object mentions at all.

Each of those is one hop. Chain them and the reach of a seemingly modest grant
is unbounded: a CI runner with `patch deployments` in one namespace becomes the
operator that runs there, which has `bind`, which is cluster-admin. Nobody
resolves that by reading YAML — and the clusters where it matters are precisely
the ones too large to read. What is needed is a graph search, and the edges are
not the obvious ones.

This tool is that graph search, offline, over a dump you already have.

## Install

```
pip install .
```

Python 3.11 or newer. No dependencies, so nothing is pulled in and nothing has
to be vetted.

To run it without installing:

```
PYTHONPATH=src python -m rbac_paths.cli --help
```

## Input

JSON only, from `kubectl`:

```
kubectl get clusterroles,clusterrolebindings,roles,rolebindings,\
  serviceaccounts,pods -A -o json > cluster.json
```

YAML is deliberately not supported. Parsing it would mean a dependency, and a
dependency on a YAML parser is a parser you have to trust with input somebody
else may have handed you. `kubectl -o json` produces exactly what this reads,
so nothing is lost.

Two optional additions make the output sharper, and the tool says so when they
are missing:

```
kubectl get nodes,namespaces -o json >> cluster.json
```

`nodes` lets control-plane nodes be identified by label rather than inferred
from what runs on them. `namespaces` carries the
`pod-security.kubernetes.io/enforce` label, so the host-access edges can be
decided per namespace instead of assumed. `--dump` accepts a file, a directory
of `.json` files, `-` for stdin, and may be repeated.

## Usage

### Paths from one subject to cluster-admin

```
$ rbac-paths escalate --dump examples/cluster-vulnerable.json \
    --from sa:ci:pipeline-runner --max-paths 2
from: ServiceAccount ci/pipeline-runner  (sa:ci:pipeline-runner)
to:   cluster-admin (effective full control)

2 paths found, shortest first.
(result limit reached; raise --max-paths to see more)

path 1: 2 hops, worst severity critical
  1. [RBAC-007 high] may `create pods` in namespace ci, so it can project the token of ServiceAccount ci/buildkit into a container it controls
     -> ServiceAccount ci/buildkit
     rule: verbs=['get', 'list', 'watch', 'create', 'patch', 'delete'] apiGroups=[""] resources=['pods']
     from: RoleBinding ci/build-runner -> Role ci/build-runner
     do:   kubectl run pwn-buildkit -n ci --image=registry.example/pause:latest --overrides='{"spec":{"serviceAccountName":"buildkit"}}' then read /var/run/secrets/kubernetes.io/serviceaccount/token
  2. [RBAC-006 critical] may `create` mutatingwebhookconfigurations, so it can register a mutating webhook that sees or rewrites every matching admission request in the cluster
     -> cluster-admin (effective full control)
     rule: verbs=['get', 'list', 'create', 'update', 'patch'] apiGroups=['admissionregistration.k8s.io'] resources=['mutatingwebhookconfigurations']
     from: ClusterRoleBinding tenant-admin-ci -> ClusterRole tenant-admin; aggregated from ClusterRole mesh-sidecar-injector
     do:   kubectl auth can-i create mutatingwebhookconfigurations

path 2: 2 hops, worst severity critical
  1. [RBAC-008 critical] may `create pods` in namespace ci, which enforces the privileged Pod Security Standard, so the pod may mount hostPath / and run privileged on node cp-1
     -> node cp-1
     rule: verbs=['get', 'list', 'watch', 'create', 'patch', 'delete'] apiGroups=[""] resources=['pods']
     from: RoleBinding ci/build-runner -> Role ci/build-runner
     do:   create a pod in ci with spec.volumes[].hostPath.path=/ and securityContext.privileged=true, pinned with spec.nodeName=cp-1
  2. [RBAC-021 critical] node cp-1 is a control-plane node (labelled node-role.kubernetes.io/control-plane), so its filesystem holds the API server's client certificates and the service-account signing key
     -> cluster-admin (effective full control)
     from: implied by the previous step
     do:   read the control-plane PKI directory and the service-account signing key from the host filesystem

2 related observation(s) that are not themselves a hop:
  [RBAC-008 medium] [platform] may `create deployments.apps`, which the controller turns into pods, in namespace platform, but the namespace enforces the restricted Pod Security Standard, which rejects hostPath, privileged, hostPID and hostNetwork. Host access is blocked unless the policy is bypassed.
  [RBAC-009 medium] [platform] may `create deployments.apps`, which the controller turns into pods, in namespace platform and may pin spec.nodeName=cp-1, a control-plane node - Pod Security Admission does not restrict nodeName. The restricted standard does block the host mounts that would make the placement useful.
```

The same subject in the hardened variant of the same cluster:

```
$ rbac-paths escalate --dump examples/cluster-hardened.json \
    --from sa:ci:pipeline-runner
from: ServiceAccount ci/pipeline-runner  (sa:ci:pipeline-runner)
to:   cluster-admin (effective full control)

No escalation path found.

This is a statement about the rules in the dump, not about the cluster: a path through a CustomResourceDefinition, an admission controller or a workload's own API is not visible here. See 'what this tool does not do' in the README.
```

`--to` takes a narrower target than cluster-admin:
`rbac-paths escalate --dump cluster.json --from sa:ci:pipeline-runner --to
get:secrets`. The last hop of such a path is labelled `TARGET` rather than a
rule id, because holding the permission you asked about is the end of the
search rather than an escalation primitive.

### Who can do a thing

```
$ rbac-paths who-can --dump examples/cluster-vulnerable.json create pods/exec
who can `create pods/exec`:

Group system:masters
  scope: all namespaces
  via group: system:masters
  rule: verbs=['*'] apiGroups=['*'] resources=['*']
        ClusterRoleBinding cluster-admin -> ClusterRole cluster-admin; via group system:masters (all namespaces)

ServiceAccount ci/pipeline-runner
  scope: ci
  rule: verbs=['create', 'get'] apiGroups=[""] resources=['pods/exec']
        RoleBinding ci/build-runner -> Role ci/build-runner (namespace ci)

notes on this query:
  - `create pods/exec` addresses a named object, so a rule with resourceNames can restrict it; pass --name to ask about one object
  - a rule must name pods/exec, */exec or * to match: a rule listing only pods does not cover its subresources
```

### Audit the whole dump

```
$ rbac-paths audit --dump examples/cluster-vulnerable.json
rbac-paths audit

input: cluster-vulnerable.json
  roles=3, clusterRoles=11, roleBindings=4, clusterRoleBindings=9, serviceAccounts=13, pods=7, secrets=4, nodes=3, namespaces=5

input warnings:
  - ClusterRoleBinding broken-legacy-binding: roleRef.kind=Role is invalid and grants nothing, ignored

10 subject(s) reach cluster-admin, shortest path first:
  Group system:masters: 1 hop(s) via RBAC-001
  Group system:serviceaccounts:observability: 1 hop(s) via RBAC-014
  ServiceAccount ci/buildkit: 1 hop(s) via RBAC-006
  ServiceAccount kube-system/node-agent: 1 hop(s) via RBAC-016
  ServiceAccount observability/default: 1 hop(s) via RBAC-014
  ServiceAccount observability/metrics-collector: 1 hop(s) via RBAC-014
  ServiceAccount platform/flux-reconciler: 1 hop(s) via RBAC-003
  ServiceAccount platform/policy-composer: 1 hop(s) via RBAC-002
  User support-engineer: 1 hop(s) via RBAC-004
  ServiceAccount ci/pipeline-runner: 2 hop(s) via RBAC-007 -> RBAC-006

escalation primitives present, worst first:

[RBAC-001 critical] Wildcard verbs on wildcard resources, cluster-wide
  1 escalation edge(s), 0 note(s)
  - Group system:masters -> cluster-admin (effective full control)
    holds wildcard verbs on wildcard resources in every namespace
    from: ClusterRoleBinding cluster-admin -> ClusterRole cluster-admin; via group system:masters

[RBAC-002 critical] `escalate` verb on roles or clusterroles
  1 escalation edge(s), 0 note(s)
  - ServiceAccount platform/policy-composer -> cluster-admin (effective full control)
    holds `escalate` on clusterroles and can rewrite ClusterRole metrics-reader, which is already bound to it, so the new rules need no new binding
...
```

The listing continues through every primitive present; the full output of that
command is 241 lines, elided here at the `...`. The hardened example's audit is
four findings long, and all four are correct:

```
$ rbac-paths audit --dump examples/cluster-hardened.json
rbac-paths audit

input: cluster-hardened.json
  roles=2, clusterRoles=10, roleBindings=4, clusterRoleBindings=7, serviceAccounts=13, pods=7, secrets=3, nodes=3, namespaces=5

1 subject(s) reach cluster-admin, shortest path first:
  User cluster-operator: 1 hop(s) via RBAC-001

escalation primitives present, worst first:

[RBAC-001 critical] Wildcard verbs on wildcard resources, cluster-wide
  1 escalation edge(s), 0 note(s)
  - User cluster-operator -> cluster-admin (effective full control)
    holds wildcard verbs on wildcard resources in every namespace
    from: ClusterRoleBinding cluster-admin -> ClusterRole cluster-admin

[RBAC-005 high] `impersonate` on users or serviceaccounts
  1 escalation edge(s), 0 note(s)
  - User support-engineer -> User support-readonly
    may impersonate the user support-readonly
    from: ClusterRoleBinding support-impersonator -> ClusterRole support-impersonator

[RBAC-017 medium] Binding to an all-cluster group
  0 escalation edge(s), 1 note(s)
  - note: group:system:authenticated ClusterRoleBinding metrics-reader-all grants ClusterRole metrics-reader to system:authenticated in every namespace - that is every identity with a valid credential, including every pod

[RBAC-018 medium] Aggregated ClusterRole picks up a label-matching role
  0 escalation edge(s), 1 note(s)
  - note: ClusterRole tenant-admin aggregates mesh-sidecar-reader by label, so whoever holds tenant-admin holds those rules too

Run `rbac-paths --explain <rule-id>` for the mechanism and remediation.
```

A cluster with no cluster-admin binding at all would be the surprising result,
so `user:cluster-operator` is reported rather than suppressed. That is the
intended reading of this output: the tool states what is there, and you decide
which of it is deliberate.

### Draw the graph

```
$ rbac-paths escalate --dump examples/cluster-vulnerable.json \
    --from sa:ci:pipeline-runner --max-paths 2 --format dot
digraph escalation {
  rankdir="LR";
  node [shape=box, fontname="monospace"];
  "sa:ci:pipeline-runner" [label="ServiceAccount ci/pipeline-runner", shape=box];
  "sa:ci:buildkit" [label="ServiceAccount ci/buildkit", shape=box];
  "cluster-admin" [label="cluster-admin (effective full control)", shape=doubleoctagon];
  "node:cp-1" [label="node cp-1", shape=box];
  "sa:ci:pipeline-runner" -> "sa:ci:buildkit" [label="RBAC-007\nns=ci", color="#d2691e", fontsize=10];
  "sa:ci:buildkit" -> "cluster-admin" [label="RBAC-006", color="#b00020", fontsize=10];
  "sa:ci:pipeline-runner" -> "node:cp-1" [label="RBAC-008\nns=ci", color="#b00020", fontsize=10];
  "node:cp-1" -> "cluster-admin" [label="RBAC-021", color="#b00020", fontsize=10];
}
```

Pipe it into graphviz: `... --format dot | dot -Tsvg -o escalation.svg`. CI
renders both examples on every push, so the DOT is known to parse.

### Explain a rule

`rbac-paths --explain RBAC-013` prints the mechanism and the remediation.
`rbac-paths --list-rules` lists all of them. Both also exist as the `explain`
and `rules` subcommands, and `rules --format json` emits the whole catalogue.

## Escalation edges

Severity means: **critical**, reaches cluster-admin, or an identity equivalent
to it, on its own; **high**, reaches another identity, and whether *that* is
cluster-admin is what the path search answers; **medium**, widens the blast
radius or is a precondition; **low**, worth knowing, not an escalation.

| ID | Primitive | Severity | Mechanism |
|----|-----------|----------|-----------|
| RBAC-001 | `*` verbs on `*` resources, cluster-wide | critical | The first rule of `cluster-admin`. Nothing needs chaining. |
| RBAC-002 | `escalate` on roles/clusterroles | critical | Switches off permission containment for role writes. Reported as an edge only when the subject can also *write* a role already bound to it, since otherwise the new rules reach nobody; otherwise reported as an inert note. |
| RBAC-003 | `bind` on roles/clusterroles | critical | Switches off containment for binding creation. Reported as an edge only when the subject can also create the binding and a wildcard ClusterRole exists to bind. |
| RBAC-004 | `impersonate` on `groups` | critical | `system:masters` is allowed unconditionally, ahead of authorisation, and no RBAC object names it. |
| RBAC-005 | `impersonate` on `users`/`serviceaccounts` | high | Reaches whatever the impersonated identity holds, with no token theft. |
| RBAC-006 | write on `(validating\|mutating)webhookconfigurations` | critical | A webhook you register is consulted on every matching admission request, and can rewrite the object before it is persisted. |
| RBAC-007 | `create pods` | high | The pod spec names the ServiceAccount to project. Equivalent to the permissions of every ServiceAccount in the namespace. |
| RBAC-008 | `create pods` with hostPath / privileged / hostPID | critical | RBAC authorises the verb, not the spec. Suppressed where the namespace enforces `baseline` or `restricted`. |
| RBAC-009 | `create pods` with `nodeName` on a control-plane node | critical | `nodeName` bypasses the scheduler, so taints and affinity do not apply. Pod Security Admission does not restrict it. |
| RBAC-010 | `pods/exec`, `/attach`, `/portforward`, `/ephemeralcontainers` | high | Runs code in a pod that already exists, inheriting its token. |
| RBAC-011 | write on deployments / statefulsets / daemonsets / jobs / cronjobs / replicasets | high | The controller creates the pod from the template you rewrote. |
| RBAC-012 | `create serviceaccounts/token` | high | TokenRequest returns a bearer token, with no pod and no Secret. |
| RBAC-013 | `get`/`list secrets` where a legacy token Secret exists | high | Pre-1.24 auto-created token Secrets are an identity. Reported only where such a Secret is actually present. |
| RBAC-014 | `get`/`list secrets` in every namespace | critical | Every credential the cluster holds. |
| RBAC-015 | `update nodes/status` | high | Lets node labels be rewritten, so a nodeSelector-constrained workload can be attracted onto a node you control. |
| RBAC-016 | `certificatesigningrequests/approval` + `approve` on the client signer | critical | Mints a client certificate with `O=system:masters`. Both permissions are required since 1.18, and both are checked. |
| RBAC-017 | binding to `system:authenticated` / `system:unauthenticated` / `system:serviceaccounts[:ns]` | medium | The whole cluster is in those groups. Severity is raised to match what the role grants. |
| RBAC-018 | aggregated ClusterRole picking up a labelled role | medium | An operator's ClusterRole label silently adds its rules to everyone holding the aggregating role. An empty selector matches every ClusterRole. |
| RBAC-019 | wildcard `nonResourceURLs` | low | `/debug/pprof` and `/logs` among them. Information, not authority. |
| RBAC-020 | control of a node | high | Every projected token of every pod on that node is a file on it. |
| RBAC-021 | control of a control-plane node | critical | The API server's client certificates, the etcd keys, and the service-account signing key. |
| RBAC-022 | `update`/`patch pods` | high | Most of a running pod is immutable; the container image is not. Narrower than RBAC-007, hence separate. |
| RBAC-023 | `create secrets` | high | 1.24 stopped *auto*-creating token Secrets. The token controller still populates one made by hand. |
| RBAC-024 | `nodes/proxy` | critical | Forwards to the kubelet's own HTTP server and its `/run` and `/exec` endpoints, without touching `pods/exec`. |

## Semantics it gets right

These are the places a checklist diverges from the authorizer. Each is covered
by tests in `tests/test_matching.py` and `tests/test_resolver.py`.

**Subresources are separate resource strings.** A rule listing `pods` does not
cover `pods/exec`. A rule must name `pods/exec`, `*/exec`, or `*`.

**`*` in `resources` does cover subresources.** Upstream `ResourceMatches`
returns true for `*` before it looks at the subresource at all, so a wildcard
resource rule in a namespace really is exec into every pod in it. This is worth
stating plainly because it is often described the other way round.

**`*` in `apiGroups` matters, and the core group is the empty string.** A rule
with `apiGroups: [""]` does not cover `deployments.apps`, and one with
`apiGroups: ["apps"]` does not cover `pods`.

**`resourceNames` restricts a rule, and cannot authorise a nameless request.**
The authorizer is given no object name for `list`, `watch`, `deletecollection`,
or for `create` on a resource — `create` carries the name in the request body.
A rule with `resourceNames` therefore grants nothing at all for those verbs.
`create` on a *subresource* is the exception: `create serviceaccounts/token`
addresses `.../serviceaccounts/<name>/token`, so the name *is* known and
`resourceNames` does restrict it. The same holds for `pods/exec`. Getting this
backwards in either direction produces a wrong answer, so both directions are
tested.

**Role versus ClusterRole scope.** A ClusterRole's rules apply cluster-wide
through a ClusterRoleBinding and inside one namespace through a RoleBinding. A
RoleBinding may only reference a Role in its own namespace. A ClusterRoleBinding
may not reference a Role at all; the API server rejects that, and so does this
tool, with a warning rather than silently.

**A namespaced grant of a cluster-scoped resource authorises nothing.** A
RoleBinding to a ClusterRole that grants `get nodes` grants no node access,
because there is no namespaced Node to authorise. `users` and `groups`, the
virtual resources the `impersonate` verb uses, are cluster-scoped too.

There is one carve-out, and it is real: the `bind` check the API server
performs when a RoleBinding is created carries the *binding's* namespace even
when the referenced role is a ClusterRole. That is what makes the documented
`role-grantor` pattern work — a namespaced Role with `resources:
["clusterroles"]`, `verbs: ["bind"]` and `resourceNames: ["admin", "edit",
"view"]` lets its holder create RoleBindings in that one namespace referencing
those ClusterRoles. The tool models that carve-out and nothing wider.

**Aggregation is recomputed, not trusted.** A ClusterRole with an
`aggregationRule` has its rules filled in by the controller-manager from every
ClusterRole whose labels match a selector. A dump from a running cluster
usually has the merged rules written back; a dump of un-applied manifests does
not. The union is recomputed either way, the contributing role is named in the
output, duplicates are collapsed, and a cycle between two aggregating roles
terminates. An `aggregationRule` containing an empty selector matches every
ClusterRole in the cluster, and is reported as critical.

**Group membership is what the API server synthesises.** Every service account
is in `system:serviceaccounts`, `system:serviceaccounts:<its namespace>` and
`system:authenticated`. Every authenticated user is in `system:authenticated`.
`system:anonymous` is in `system:unauthenticated` and nothing else. There is no
in-cluster object mapping a user to a group — that comes from the
authenticator, so it cannot be read from a dump; `--group` declares it when you
know it.

**Paths are simple and de-duplicated.** No node repeats within a path, which is
what keeps the search finite: two service accounts that can each exec into the
other's pods form a cycle, and real clusters have them. Two paths that differ
only in which rule permitted a hop are both reported, because they are
different things to fix.

## Kubernetes version note

The authorizer semantics modelled here are those of Kubernetes **1.29 through
1.34**, in which the matching functions
(`VerbMatches`, `APIGroupMatches`, `ResourceMatches`, `ResourceNameMatches`,
`NonResourceURLMatches`) are unchanged. Two behaviours are version-dependent
and handled explicitly:

- **1.24** stopped auto-creating a `kubernetes.io/service-account-token` Secret
  for every ServiceAccount (`LegacyServiceAccountTokenNoAutoGeneration`).
  `get secrets` is therefore weaker than it used to be: RBAC-013 is reported
  only for service accounts that actually have such a Secret in the dump, and
  where none exists the tool says so instead of implying an identity that is
  not there. The flip side is RBAC-023: the change stopped *automatic*
  creation, not the token controller populating a Secret created by hand, so
  `create secrets` still mints a long-lived token.
- **1.18** separated CSR approval into two permissions: write on
  `certificatesigningrequests/approval` *and* `approve` on `signers` for the
  signer in question. RBAC-016 requires both, plus the ability to submit a
  request, and reports a partial holding as a note rather than a finding.

Pod Security Admission levels are read from the
`pod-security.kubernetes.io/enforce` namespace label, which is GA from 1.25.
Where the label is absent the tool assumes `privileged`, which is the API
server's own default; `--assume-psa` changes that assumption.

## What this tool does not do

- **It does not read a cluster.** It has no client and opens no socket. A dump
  is a snapshot, and a snapshot can be stale.
- **It does not know about admission control beyond the PSA label.** Gatekeeper,
  Kyverno, a validating webhook or a custom admission plugin may block the
  pod spec that RBAC-008 and RBAC-009 depend on. Those two edges mean "possible
  unless an admission policy denies it", and the output says which Pod Security
  Standard it assumed.
- **It does not model CustomResourceDefinitions.** A CRD whose controller runs
  privileged work on your behalf is an escalation path, and it is invisible
  here: the tool sees the verb on the custom resource but cannot know what the
  controller does with it. Wildcard rules over custom API groups are reported,
  which is the most it can honestly say.
- **It does not know your authenticator.** Group membership from OIDC claims or
  a certificate's Organization field is not in any cluster object. Supply it
  with `--group`.
- **It does not resolve a Role referenced by a binding but absent from the
  dump.** A partial dump gives a partial answer; a role that cannot be found
  contributes no rules, so under-reporting is the failure mode.
- **It does not prioritise by exploitability in your environment.** Severities
  are properties of the primitive, not of your cluster's network position,
  monitoring or blast radius.
- **"No escalation path found" is a statement about the rules in the dump.** It
  is not a clean bill of health.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Ran successfully and found nothing. `escalate`: no path. `audit`: no primitive. `who-can` always exits 0 on success — a query having an answer is not a finding. |
| 1 | Ran successfully and found something. `--exit-zero` forces 0 instead, for a report you want to read without failing a pipeline. |
| 2 | Usage error: a bad flag, an unparseable subject or target, or a format the subcommand does not produce. Also what `rbac-paths` with no subcommand returns, after printing help. |
| 3 | Input error: a dump that is missing, unreadable, or not the JSON shape `kubectl -o json` produces. |
| 4 | An unexpected internal error, which is a bug. `--traceback` shows it. |

## Examples

`examples/` holds two complete cluster dumps. Both are **entirely fabricated**:
invented namespaces and service accounts, `registry.example` images, and a
single obviously synthetic placeholder wherever a token value would be. Nothing
in them came from any real cluster.

- `cluster-vulnerable.json` — a CI service account with `patch deployments` in
  a namespace that runs a privileged operator, a legacy token Secret that
  survived an upgrade, a `ClusterRoleBinding` to `system:authenticated`, an
  aggregated ClusterRole picking up an operator's permissions, a node-lifecycle
  operator that can approve certificate signing requests, and a Secret read
  pinned by `resourceNames` so the restriction can be seen to hold. Every one
  of the 24 catalogued rules fires somewhere in it, which
  `tests/test_examples.py` asserts.
- `cluster-hardened.json` — the same shape with the escalations removed. The
  same `escalate --from sa:ci:pipeline-runner` query returns nothing.

## Tests

```
$ python -m unittest discover -s tests -t . -v
...
Ran 444 tests in 0.222s

OK
```

(The per-test lines are elided at the `...`.)

The suite is entirely offline — every assertion is a pure function over JSON
already in the repository — so there is no cluster to start and nothing to wait
for. It covers each of the 24 edge rules with a positive and a negative case,
wildcard and `resourceNames` semantics in both directions, Role versus
ClusterRole scope, aggregation including cycles and empty selectors, group
membership, path de-duplication and cycle termination, every output format, and
every documented exit code.

`tests/test_no_network.py` enforces the offline claim structurally rather than
by assertion: it parses every module in the package and fails if any import is
not on an allow list of standard-library modules, which excludes `socket`,
`ssl`, `urllib`, `http`, `requests`, `subprocess` and the Kubernetes client.
It also checks that `pyproject.toml` declares no dependencies.

CI runs the suite on Python 3.11, 3.12 and 3.13, then runs the CLI end to end:
the vulnerable example must yield the three documented rule chains, the
hardened example must yield none for the same subject, `who-can` must respect
`resourceNames`, the DOT output must parse with graphviz, and every exit code
above must be what this README says it is.

## Authorisation

This is a read-only analyser of a file you already have. It makes no request to
any cluster.

The `do:` line on each hop describes the action a tester would take to confirm
the finding. Those actions use permissions the subject already holds, so they
are within what an engagement that granted you that subject's credentials has
already authorised — but running them still changes a cluster, and some of them
(creating a privileged pod, registering an admission webhook, approving a
certificate) are not reversible by deleting the object you created. Confirm the
scope of your authorisation before you run any of them, and prefer `kubectl
auth can-i` to the destructive form where it answers the same question.

## Licence

MIT. See [LICENSE](LICENSE).
