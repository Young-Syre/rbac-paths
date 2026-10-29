"""The escalation-edge catalogue.

Each entry names one primitive: a permission, or a small combination of
permissions, that converts into an identity you did not start with.  The
``mechanism`` field says why it works, because a finding you cannot explain is
a finding nobody will fix.

Severities, as used throughout this tool:

``critical``
    Reaches cluster-admin, or an identity equivalent to it, on its own.
``high``
    Reaches another identity.  Whether that is cluster-admin depends on what
    the other identity holds, which is what the path search is for.
``medium``
    Widens the blast radius or is a precondition for the above.
``low``
    Worth knowing about, not an escalation by itself.

Docs references are to kubernetes.io and are correct for 1.29-1.34.
"""

from __future__ import annotations

from dataclasses import dataclass

RBAC_DOC = "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
CONTAINMENT_DOC = RBAC_DOC + "#privilege-escalation-prevention-and-bootstrapping"
PSS_DOC = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
IMPERSONATION_DOC = (
    "https://kubernetes.io/docs/reference/access-authn-authz/authentication/"
    "#user-impersonation"
)
SA_TOKEN_DOC = (
    "https://kubernetes.io/docs/concepts/configuration/secret/#service-account-token-secrets"
)
CSR_DOC = "https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/"
WEBHOOK_DOC = (
    "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/"
)
NODE_AUTH_DOC = "https://kubernetes.io/docs/reference/access-authn-authz/node/"

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class EdgeRule:
    id: str
    title: str
    severity: str
    mechanism: str
    remediation: str
    references: tuple[str, ...] = ()


_RULES: tuple[EdgeRule, ...] = (
    EdgeRule(
        id="RBAC-001",
        title="Wildcard verbs on wildcard resources, cluster-wide",
        severity="critical",
        mechanism=(
            "A rule with verbs ['*'], apiGroups ['*'] and resources ['*'] reaching a "
            "subject through a ClusterRoleBinding is the first rule of cluster-admin. "
            "Nothing further needs to be chained: the subject can already write RBAC, "
            "read every Secret and create privileged pods anywhere."
        ),
        remediation=(
            "Enumerate the verbs and resources the workload needs and grant those. If "
            "the grant is genuinely administrative, bind it to a named human identity "
            "rather than a ServiceAccount a pod can read a token for."
        ),
        references=(RBAC_DOC,),
    ),
    EdgeRule(
        id="RBAC-002",
        title="`escalate` verb on roles or clusterroles",
        severity="critical",
        mechanism=(
            "Writing a Role or ClusterRole is normally constrained by permission "
            "containment: the API server refuses to let you grant a permission you do "
            "not hold. The `escalate` verb switches that check off. With it, the "
            "subject rewrites any role it can write into a wildcard role and is "
            "cluster-admin at the next request."
        ),
        remediation=(
            "Remove `escalate`. It exists for controllers that compose roles, and "
            "almost nothing else has cause to hold it. If a controller needs it, "
            "restrict the rule with resourceNames to the roles it actually composes."
        ),
        references=(CONTAINMENT_DOC,),
    ),
    EdgeRule(
        id="RBAC-003",
        title="`bind` verb on roles or clusterroles",
        severity="critical",
        mechanism=(
            "Creating a binding is also containment-checked: you may only bind a role "
            "whose permissions you already hold. The `bind` verb removes that check "
            "for the named roles. With `bind` unrestricted, the subject creates a "
            "ClusterRoleBinding from itself to the cluster-admin ClusterRole that "
            "every cluster already ships."
        ),
        remediation=(
            "Remove `bind`, or restrict it with resourceNames to the specific roles "
            "the subject is allowed to hand out, and make sure none of those roles is "
            "itself administrative."
        ),
        references=(CONTAINMENT_DOC,),
    ),
    EdgeRule(
        id="RBAC-004",
        title="`impersonate` on groups reaches system:masters",
        severity="critical",
        mechanism=(
            "`system:masters` is wired into the API server ahead of authorization: a "
            "request from that group is allowed unconditionally and no RBAC object "
            "mentions it. A subject that may impersonate an arbitrary group sets "
            "Impersonate-Group: system:masters and has unconditional access."
        ),
        remediation=(
            "Restrict the rule with resourceNames to the exact groups that may be "
            "impersonated, and never include system:masters. Impersonation is logged "
            "with both identities, so audit on the impersonator rather than trusting "
            "the grant."
        ),
        references=(IMPERSONATION_DOC,),
    ),
    EdgeRule(
        id="RBAC-005",
        title="`impersonate` on users or serviceaccounts",
        severity="high",
        mechanism=(
            "The subject sends its own credential with an Impersonate-User header and "
            "the API server authorizes the request as the impersonated identity. It "
            "reaches whatever that identity holds, with no token theft involved."
        ),
        remediation=(
            "Restrict impersonation to named identities with resourceNames, and only "
            "to identities less privileged than the impersonator."
        ),
        references=(IMPERSONATION_DOC,),
    ),
    EdgeRule(
        id="RBAC-006",
        title="Write access to admission webhook configurations",
        severity="critical",
        mechanism=(
            "A MutatingWebhookConfiguration the subject creates is consulted on every "
            "matching admission request in the cluster. The webhook can rewrite any "
            "object before it is persisted - adding a privileged container to a "
            "control-plane workload, for instance - and a ValidatingWebhook sees the "
            "full body of every object written, including Secrets."
        ),
        remediation=(
            "Treat admission configuration as control-plane configuration. Remove the "
            "grant, or restrict it with resourceNames to the configuration the "
            "component owns."
        ),
        references=(WEBHOOK_DOC,),
    ),
    EdgeRule(
        id="RBAC-007",
        title="`create pods` grants every service account in the namespace",
        severity="high",
        mechanism=(
            "A pod spec names the ServiceAccount whose token is projected into the "
            "container. RBAC has no concept of which service accounts a subject may "
            "mount, so `create pods` in a namespace is equivalent to holding the "
            "permissions of every ServiceAccount in it. The attacker reads the token "
            "from the projected volume inside their own pod."
        ),
        remediation=(
            "Move pod creation behind a controller the subject can only ask through, "
            "or split the namespace so that privileged service accounts do not share "
            "one with workloads whose creation is delegated."
        ),
        references=(RBAC_DOC,),
    ),
    EdgeRule(
        id="RBAC-008",
        title="`create pods` with hostPath, privileged or hostPID reaches node root",
        severity="critical",
        mechanism=(
            "RBAC authorizes the verb, not the pod spec. A subject that may create a "
            "pod may set securityContext.privileged, hostPID, hostNetwork or a "
            "hostPath volume mounting /, and read the kubelet's client certificate "
            "and every container's projected token off the node filesystem. Only "
            "admission control - Pod Security Admission or a policy engine - can stop "
            "this, and this tool cannot see policy engines."
        ),
        remediation=(
            "Enforce the `baseline` or `restricted` Pod Security Standard on the "
            "namespace with the pod-security.kubernetes.io/enforce label. Label the "
            "namespace rather than relying on the workload to behave."
        ),
        references=(PSS_DOC,),
    ),
    EdgeRule(
        id="RBAC-009",
        title="`create pods` with nodeName pinned to a control-plane node",
        severity="critical",
        mechanism=(
            "spec.nodeName bypasses the scheduler, so a subject that may create pods "
            "chooses the node. Pinned to a control-plane node, the pod can read the "
            "API server's client certificates and the etcd peer keys from the host "
            "filesystem. Pod Security Admission does not restrict nodeName, so a "
            "`restricted` namespace does not prevent the choice of node - only the "
            "host mounts that make it useful."
        ),
        remediation=(
            "Keep control-plane nodes tainted and do not grant pod creation in "
            "namespaces whose workloads tolerate those taints. Combine with a "
            "`restricted` Pod Security Standard so a pinned pod gains no host access."
        ),
        references=(PSS_DOC,),
    ),
    EdgeRule(
        id="RBAC-010",
        title="`create` on pods/exec, pods/attach, pods/portforward or pods/ephemeralcontainers",
        severity="high",
        mechanism=(
            "These subresources run code inside a pod that is already running, so the "
            "subject inherits that pod's projected ServiceAccount token and its "
            "network position without creating anything. pods/ephemeralcontainers is "
            "the same reach with a container image of the attacker's choosing."
        ),
        remediation=(
            "Grant exec only in namespaces whose workloads hold nothing the subject "
            "should not, and prefer a break-glass identity over a standing grant."
        ),
        references=(RBAC_DOC,),
    ),
    EdgeRule(
        id="RBAC-011",
        title="Write access to a workload controller is pod creation, one reconcile later",
        severity="high",
        mechanism=(
            "A Deployment, StatefulSet, DaemonSet, Job, CronJob or ReplicaSet is a pod "
            "template plus a controller that will act on it. `patch` or `update` on "
            "any of them lets the subject rewrite the template - including its "
            "serviceAccountName, volumes and securityContext - and the controller "
            "creates the pod with the subject's spec. The subject never needs `create "
            "pods` itself."
        ),
        remediation=(
            "Treat write access to workload objects as equivalent to pod creation when "
            "assessing a grant, and scope it to the namespaces the subject owns."
        ),
        references=(RBAC_DOC,),
    ),
    EdgeRule(
        id="RBAC-012",
        title="`create` on serviceaccounts/token mints a credential",
        severity="high",
        mechanism=(
            "The TokenRequest subresource returns a bearer token for the named "
            "ServiceAccount. This is the supported way to get a token and needs no "
            "pod and no Secret, so it leaves nothing behind but an audit entry. An "
            "unrestricted rule mints a token for any service account in reach."
        ),
        remediation=(
            "Restrict the rule with resourceNames to the service accounts the subject "
            "is meant to mint for. Note that resourceNames does work here: "
            "TokenRequest is a subresource of a named object, so the authorizer does "
            "see the name."
        ),
        references=("https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/",),
    ),
    EdgeRule(
        id="RBAC-013",
        title="`get`/`list` on secrets reaches service-account tokens that exist as Secrets",
        severity="high",
        mechanism=(
            "Before 1.24 every ServiceAccount had a long-lived token Secret created "
            "for it automatically, so `get secrets` in a namespace was every identity "
            "in it. Since 1.24 (LegacyServiceAccountTokenNoAutoGeneration) those "
            "Secrets are no longer created, so this edge only exists where such a "
            "Secret is still present - left over from an upgrade, or created on "
            "purpose. This tool reports the edge only for service accounts that have "
            "a kubernetes.io/service-account-token Secret in the dump; read access to "
            "other Secrets is still credential disclosure, reported as RBAC-014 when "
            "it is cluster-wide."
        ),
        remediation=(
            "Delete leftover kubernetes.io/service-account-token Secrets and use the "
            "TokenRequest API instead. Then narrow the Secret read grant with "
            "resourceNames."
        ),
        references=(SA_TOKEN_DOC,),
    ),
    EdgeRule(
        id="RBAC-014",
        title="`get`/`list` on secrets across all namespaces",
        severity="critical",
        mechanism=(
            "Cluster-wide Secret read is every credential the cluster holds: database "
            "passwords, cloud provider keys, the tokens of any service account that "
            "still has a Secret, and whatever a controller stored. It is not a path "
            "to cluster-admin through the API so much as a way around needing one."
        ),
        remediation=(
            "Replace the cluster-wide grant with per-namespace RoleBindings, or with "
            "resourceNames for the specific Secrets a controller reads. `list` and "
            "`watch` cannot be restricted by resourceNames, so a controller that "
            "needs to watch needs a narrower namespace instead."
        ),
        references=(RBAC_DOC,),
    ),
    EdgeRule(
        id="RBAC-015",
        title="`update` on nodes/status allows node label manipulation",
        severity="high",
        mechanism=(
            "The status subresource of a Node can carry metadata changes, so write "
            "access to it lets a subject add or remove node labels. Labels decide "
            "where a nodeSelector-constrained workload runs, so the subject can "
            "attract a privileged workload onto a node it controls, or away from the "
            "nodes an operator expects."
        ),
        remediation=(
            "Only the kubelet and the cloud-controller-manager need to write node "
            "status. Remove the grant from anything else."
        ),
        references=(NODE_AUTH_DOC,),
    ),
    EdgeRule(
        id="RBAC-016",
        title="`create` on certificatesigningrequests/approval mints any identity",
        severity="critical",
        mechanism=(
            "A CSR for the kubernetes.io/kube-apiserver-client signer, once approved, "
            "produces a client certificate the API server trusts. The subject names "
            "the identity: CN=anything for a user, O=system:masters for unconditional "
            "access, or CN=system:node:<node> for a kubelet. Approval and signing are "
            "separate permissions, so this is reported when the subject can approve "
            "and a signer is running - which it is on any cluster where kubeadm or a "
            "managed provider set it up."
        ),
        remediation=(
            "Remove approval rights from anything but the controller that owns them, "
            "and alert on approvals of the kube-apiserver-client signer."
        ),
        references=(CSR_DOC,),
    ),
    EdgeRule(
        id="RBAC-017",
        title="Binding to an all-cluster group",
        severity="medium",
        mechanism=(
            "system:authenticated contains every identity with any valid credential, "
            "including every pod's service account. system:serviceaccounts contains "
            "every pod in the cluster, and system:serviceaccounts:<ns> every pod in a "
            "namespace. system:unauthenticated contains anyone who can reach the API "
            "server port. A ClusterRoleBinding to one of these grants its role to all "
            "of them, which is how a single convenience binding becomes a cluster-wide "
            "permission. The severity reported here is the severity of what the role "
            "actually grants."
        ),
        remediation=(
            "Bind to the specific service accounts or to a narrower group. If the "
            "intent really is cluster-wide read, confirm the role grants no Secret "
            "access and no write verbs."
        ),
        references=(RBAC_DOC,),
    ),
    EdgeRule(
        id="RBAC-018",
        title="Aggregated ClusterRole picks up a label-matching role",
        severity="medium",
        mechanism=(
            "A ClusterRole with an aggregationRule has its rules filled in by the "
            "controller-manager from every ClusterRole whose labels match a selector. "
            "An operator that ships a ClusterRole labelled "
            "rbac.authorization.k8s.io/aggregate-to-edit: \"true\" has silently added "
            "its permissions to everyone holding `edit`. An aggregationRule containing "
            "an empty selector matches every ClusterRole in the cluster."
        ),
        remediation=(
            "Review what each aggregation label currently selects after installing an "
            "operator, and never ship an aggregationRule with an empty selector."
        ),
        references=(RBAC_DOC + "#aggregated-clusterroles",),
    ),
    EdgeRule(
        id="RBAC-019",
        title="Wildcard nonResourceURLs",
        severity="low",
        mechanism=(
            "nonResourceURLs covers paths outside the resource model: /healthz, "
            "/metrics, /debug/pprof, /logs and the OpenAPI document. A wildcard grant "
            "exposes whatever those endpoints expose on this build, which is "
            "information rather than authority - but /debug/pprof and /logs are more "
            "than most operators expect to have published."
        ),
        remediation=(
            "List the paths the subject needs. /healthz, /livez, /readyz and /version "
            "cover the usual case."
        ),
        references=(RBAC_DOC,),
    ),
    EdgeRule(
        id="RBAC-020",
        title="Node control yields every service-account token of pods on that node",
        severity="high",
        mechanism=(
            "A projected service-account token is a file on the node, under the "
            "kubelet's pod directory. Root on the node reads every one of them, so "
            "control of a node is the union of the identities of the pods scheduled "
            "there - plus the kubelet's own credential, which the Node authorizer "
            "allows to read the Secrets and ConfigMaps of those same pods."
        ),
        remediation=(
            "Spread privileged workloads away from nodes that run delegated "
            "workloads, and remove the RBAC grants that allowed node control in the "
            "first place: this edge is only reachable through one of the pod-creation "
            "or node-identity primitives above."
        ),
        references=(NODE_AUTH_DOC,),
    ),
    EdgeRule(
        id="RBAC-021",
        title="Control-plane node control is cluster-admin",
        severity="critical",
        mechanism=(
            "A control-plane node holds the API server's own client certificates, the "
            "etcd peer and client keys, and the service-account signing key. Any of "
            "the three is full control of the cluster; the signing key also mints "
            "service-account tokens offline, with nothing written to the audit log."
        ),
        remediation=(
            "Nothing but the control-plane components should run on these nodes. "
            "Taint them, and audit which workloads tolerate the taint."
        ),
        references=(NODE_AUTH_DOC,),
    ),
    EdgeRule(
        id="RBAC-022",
        title="`update`/`patch` on pods swaps a running pod's container image",
        severity="high",
        mechanism=(
            "Most of a running pod's spec is immutable, so `patch pods` is not the "
            "same as `create pods`. The container image is mutable, though: the "
            "subject points a container at an image it controls and the kubelet runs "
            "it with that pod's projected token and volumes. Reported separately from "
            "RBAC-007 because it reaches only the service accounts of pods that "
            "already exist, not every account in the namespace."
        ),
        remediation=(
            "Grant `get`, `list` and `watch` on pods for observability and leave the "
            "write verbs out. Where a controller must write, scope it by namespace."
        ),
        references=(RBAC_DOC,),
    ),
    EdgeRule(
        id="RBAC-023",
        title="`create` on secrets mints a long-lived service-account token",
        severity="high",
        mechanism=(
            "The 1.24 change stopped the *automatic* creation of service-account token "
            "Secrets. It did not stop the token controller populating one that is "
            "created by hand: a Secret of type kubernetes.io/service-account-token "
            "carrying the kubernetes.io/service-account.name annotation is still "
            "filled in with a valid token, which is long-lived and not bound to a pod. "
            "`create secrets` in a namespace is therefore a credential for every "
            "service account in it."
        ),
        remediation=(
            "Remove Secret creation where it is not needed, and alert on Secrets of "
            "type kubernetes.io/service-account-token being created. Use TokenRequest "
            "for anything that genuinely needs a token."
        ),
        references=(SA_TOKEN_DOC,),
    ),
    EdgeRule(
        id="RBAC-024",
        title="Access to nodes/proxy reaches the kubelet API",
        severity="critical",
        mechanism=(
            "The nodes/proxy subresource forwards to the kubelet's own HTTP server, "
            "which has its own endpoints and its own authorization - /exec, /run and "
            "/attach among them. A subject with nodes/proxy runs commands in any "
            "container on the node without touching pods/exec, so an audit that only "
            "looks at pods/exec misses it entirely."
        ),
        remediation=(
            "Remove nodes/proxy. Metrics scrapers want nodes/metrics or "
            "nodes/stats, not proxy."
        ),
        references=(NODE_AUTH_DOC,),
    ),
)

RULES: dict[str, EdgeRule] = {rule.id: rule for rule in _RULES}


def all_rules() -> list[EdgeRule]:
    return list(_RULES)


def get_rule(rule_id: str) -> EdgeRule | None:
    return RULES.get(rule_id.upper())


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, len(SEVERITIES))
