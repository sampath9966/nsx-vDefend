"""Interactive menu.

The full menu prints once. After that only a compact one-line prompt appears,
so the output of the action you just ran stays visible directly above the next
prompt instead of being pushed off-screen by a reprinted menu. 'm' brings the
full menu back on demand.
"""

from .actions.audit_view import act_audit_log
from .actions.author import author_menu
from .actions.bulk import act_bulk_tag
from .actions.change_ticket import act_change_ticket
from .actions.dashboard import act_dashboard
from .actions.drift import act_drift_menu
from .actions.groups import act_groups
from .actions.hygiene import act_hygiene
from .actions.parity import act_parity
from .actions.reverse import act_reverse_lookup
from .actions.tags import act_manage_tags, act_vm_tags, act_vms_by_tag
from .actions.trace import trace_menu
from .actions.verify import act_verify
from .api import DEFAULT_DOMAIN, ROLE_GM, ROLE_LABEL, ROLE_LM
from .errors import NsxError, UserAbort
from .export import offer_export
from .output import (
    W,
    ask,
    cB,
    cBC,
    cBG,
    cBY,
    cC,
    cD,
    confirm,
    err,
    say,
    set_assume_yes,
    table,
)


class AppContext:
    """Everything an action needs, assembled once in cli.main()."""

    def __init__(self, sessions, audit, exporter, taxonomy,
                 write_enabled=False, domain=DEFAULT_DOMAIN, managers=None,
                 profile=None, project=None, inventory_path=None):
        self.sessions = sessions
        self.audit = audit
        self.exporter = exporter
        self.taxonomy = taxonomy
        self.write_enabled = write_enabled
        self.domain = domain
        # Inventory entries, for commands that act on configuration rather
        # than on a live connection (login).
        self.managers = managers or []
        # Which estate, and which tenant inside it, this run is talking to.
        self.profile = profile
        self.project = project
        self.inventory_path = inventory_path

    def cache_key(self):
        """(profile, project) -- which estate and tenant a cached name
        belongs to. Completing production names into a DR command is worse
        than completing nothing."""
        return (self.profile, self.project)

    def lms(self):
        return [s for s in self.sessions if s.role == ROLE_LM]

    def close(self):
        for s in self.sessions:
            s.close()


def menu_text(mode_str):
    h = cBC("=" * W)
    d = cD("-" * 42)
    return """
{h}
  {groups}   {gsub}
  {d}
    1.  Search groups + show criteria
    2.  Search groups + criteria + VM members

  {tags}     {tsub}
  {d}
    3.  Show all tags on a VM
    4.  Find all VMs carrying a specific tag
    5.  Add / remove tags                      {audit}

  {bulk}
  {d}
    6.  Bulk tag from CSV                      {dry}
    7.  Reverse lookup: VM -> groups -> rules  {rl}
    8.  Parity validation (static vs dynamic)
    9.  Compliance dashboard
   15.  DFW rule hygiene                       {hyg}
   16.  Drift since last snapshot              {dft}
   17.  Trace a flow: can A reach B?             {trc}
   18.  Create / edit groups and rules            {aut}

  {ops}
  {d}
   10.  Verify connectivity + API detection
   11.  View audit log / undo
   12.  Toggle write mode                      [{mode}]
   13.  Generate change ticket from CSV
   14.  List managers

    m.  Show this menu again    q.  Quit
{h}
""".format(h=h, d=d, mode=mode_str,
           groups=cB("GROUPS"), gsub=cD("(Global Manager + Local Managers)"),
           tags=cB("TAGS"), tsub=cD("(Local Managers only)"),
           bulk=cB("BULK & ANALYSIS"), ops=cB("OPERATIONS"),
           audit=cD("(audit logged)"), dry=cD("(dry-run first)"),
           rl=cD("(any member type, deduped)"),
           hyg=cD("(any-any, shadowed, unused, broken refs)"),
           dft=cD("(what changed, and who changed it)"),
           trc=cD("(policy verdict, and the data plane's)"),
           aut=cD("(dry-run first, audited, undoable)"))


def select_managers(sessions, allow_roles, allow_all=False, label=""):
    pool = [s for s in sessions if s.role in allow_roles]
    if not pool:
        say("\n  No managers of that type are connected.")
        return []
    if len(pool) == 1:
        return pool
    say("\n  Target for {}:".format(cB(label)))
    for i, s in enumerate(pool, 1):
        say("    {}. {:26s}  {:30s}  {}".format(
            i, cC(s.name), s.host, cD(ROLE_LABEL.get(s.role, "?"))))
    if allow_all:
        note = "  (tags span LMs)" if tuple(allow_roles) == (ROLE_LM,) else ""
        say("    a. ALL ({}){}".format(len(pool), note))
    say("    b. back")
    while True:
        c = ask("  Choice: ").lower()
        if allow_all and c == "a":
            return pool
        if c.isdigit() and 1 <= int(c) <= len(pool):
            return [pool[int(c) - 1]]
        say("    Invalid.")


def _mode_str(ctx):
    return cBG("READ-WRITE") if ctx.write_enabled else cBY("READ-ONLY")


def interactive(ctx):
    say(menu_text(_mode_str(ctx)))
    say("  Tip: {}".format(cD("m = menu, b = back mid-prompt, q = quit")))

    while True:
        try:
            c = ask("\n  Choice [{}{} ".format(_mode_str(ctx), cD("]:")),
                    allow_back=False).strip().lower()
        except UserAbort:
            say("\n  Bye.")
            return 0

        try:
            if c == "q":
                say("  Bye.")
                return 0

            elif c == "m":
                say(menu_text(_mode_str(ctx)))

            elif c == "14":
                say("")
                table(["Name", "Host", "Role", "Auth"],
                      [[cC(s.name), s.host, cD(ROLE_LABEL.get(s.role, "?")),
                        cD(s.auth_mode)] for s in ctx.sessions])

            elif c in ("1", "2"):
                tgt = select_managers(ctx.sessions, (ROLE_GM, ROLE_LM),
                                      allow_all=True, label="group search")
                if not tgt:
                    continue
                domain = ask("  Domain [{}]: ".format(ctx.domain), default=ctx.domain)
                needle = ask("  Name/id contains (blank=all): ", default="")
                act_groups(tgt, domain, needle, show_members=(c == "2"),
                           exporter=ctx.exporter)
                offer_export(ctx.exporter)

            elif c == "3":
                tgt = select_managers(ctx.sessions, (ROLE_LM,),
                                      allow_all=True, label="VM tag lookup")
                if not tgt:
                    continue
                vm = ask("  VM name contains: ")
                if vm:
                    act_vm_tags(tgt, vm, ctx.exporter, ctx.taxonomy)
                    offer_export(ctx.exporter)

            elif c == "4":
                tgt = select_managers(ctx.sessions, (ROLE_LM,),
                                      allow_all=True, label="tag search")
                if not tgt:
                    continue
                scope = ask("  Tag scope (blank=any): ", default="")
                tag = ask("  Tag value (blank=any): ", default="")
                if not scope and not tag:
                    say("    Give a scope, a value, or both.")
                    continue
                act_vms_by_tag(tgt, scope, tag, ctx.exporter)
                offer_export(ctx.exporter)

            elif c == "5":
                tgt = select_managers(ctx.sessions, (ROLE_LM,),
                                      allow_all=True, label="tag management")
                if not tgt:
                    continue
                vm = ask("  VM name contains: ")
                if vm:
                    act_manage_tags(tgt, vm, ctx.audit, ctx.write_enabled,
                                    ctx.taxonomy)

            elif c == "6":
                tgt = select_managers(ctx.sessions, (ROLE_LM,),
                                      allow_all=True, label="bulk tagging")
                if not tgt:
                    continue
                csv_path = ask("  CSV file path: ")
                if not csv_path:
                    continue
                say("\n  {} first ...".format(cBY("DRY RUN")))
                act_bulk_tag(tgt, csv_path, ctx.audit, ctx.write_enabled,
                             dry_run=True, taxonomy=ctx.taxonomy)
                if not ctx.write_enabled:
                    say("  {} -- enable write mode (12) to apply.".format(
                        cBY("READ-ONLY")))
                    continue
                if confirm("\n  {} [y/N]: ".format(cB("Apply for real?"))):
                    act_bulk_tag(tgt, csv_path, ctx.audit, ctx.write_enabled,
                                 dry_run=False, taxonomy=ctx.taxonomy)
                else:
                    say("  Cancelled.")

            elif c == "7":
                # Always sweeps every connected manager -- see the docstring on
                # act_reverse_lookup for why a partial selection is wrong here.
                domain = ask("  Domain [{}]: ".format(ctx.domain), default=ctx.domain)
                vm = ask("  VM name contains: ")
                if vm:
                    act_reverse_lookup(ctx.sessions, vm, domain, ctx.exporter)
                    offer_export(ctx.exporter)

            elif c == "8":
                static = ask("  Static group name/id: ")
                if not static:
                    continue
                dynamic = ask("  Dynamic group name/id: ")
                if not dynamic:
                    continue
                domain = ask("  Domain [{}]: ".format(ctx.domain), default=ctx.domain)
                act_parity(ctx.sessions, domain, static, dynamic, ctx.exporter)
                offer_export(ctx.exporter)

            elif c == "9":
                act_dashboard(ctx.sessions, ctx.exporter, ctx.taxonomy)
                offer_export(ctx.exporter)

            elif c == "15":
                act_hygiene(ctx.sessions, ctx.domain, ctx.exporter)
                offer_export(ctx.exporter)

            elif c == "16":
                act_drift_menu(ctx)
                offer_export(ctx.exporter)

            elif c == "17":
                trace_menu(ctx)
                offer_export(ctx.exporter)

            elif c == "18":
                author_menu(ctx)
                offer_export(ctx.exporter)

            elif c == "10":
                tgt = select_managers(ctx.sessions, (ROLE_GM, ROLE_LM),
                                      allow_all=True, label="verification")
                if tgt:
                    act_verify(tgt, ctx.domain)

            elif c == "11":
                act_audit_log(ctx.audit, ctx.sessions, ctx.write_enabled,
                              ctx.exporter, domain=ctx.domain)
                offer_export(ctx.exporter)

            elif c == "12":
                ctx.write_enabled = not ctx.write_enabled
                # --yes is a non-interactive gate; in the menu every write is
                # already confirmed at the prompt, so never leave it latched on.
                set_assume_yes(False)
                say("  Write mode: {}".format(
                    cBG("ENABLED") if ctx.write_enabled else cBY("DISABLED")))

            elif c == "13":
                csv_path = ask("  CSV file path: ")
                if csv_path:
                    act_change_ticket(ctx.sessions, csv_path, ctx.exporter)
                    offer_export(ctx.exporter)

            elif c == "":
                continue

            else:
                say("  Not a valid choice. ({})".format(cD("'m' for menu")))

        except UserAbort:
            say("  (backed out)")
            continue
        except NsxError as e:
            err(str(e))
        except Exception as e:  # noqa: BLE001 - menu must survive any action
            err("unexpected: {}".format(e))
        # No "press Enter to continue" + full-menu reprint here on purpose:
        # that pattern is what pushed results off-screen.
