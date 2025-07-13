# ------------------------------------------------------------------------------
# Sentio
# Project: Offchain Analyzer
# Author: Sentio Team
# Email: connectsentio@gmail.com
# Date Published: 2024-07-8
# Description: This application provides a backend API for analyzing Lua
#              code for integer overflows and potential vulnerabilities using
#              luaparser.
# ------------------------------------------------------------------------------


from flask import Flask, render_template, request, jsonify
from luaparser import ast, astnodes
import luaparser
from luaparser.astnodes import *
from flask_cors import CORS
from datetime import datetime
from ai_agent import create_security_agent, create_chat_agent
from learning_agent import create_learning_agent

app = Flask(__name__)
CORS(app)

INT_MAX = 2147483647
INT_MIN = -2147483648

vulnerabilities = []


def add_vulnerability(name, description, pattern, severity, line):
    vulnerabilities.append(
        {
            "name": name,
            "description": description,
            "pattern": pattern,
            "severity": severity,
            "line": line,
        }
    )


def is_potential_overflow(number):
    return number >= INT_MAX or number <= INT_MIN


def is_potential_underflow(number):
    return number <= INT_MIN or number >= INT_MAX


def get_line_number(node):
    if hasattr(node, "line") and node.line is not None:
        return node.line
    if hasattr(node, "_parent"):
        return get_line_number(node._parent)
    return None


def analyze_overflow_in_node(node):
    if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
        left_operand = node.left
        right_operand = node.right

        if isinstance(left_operand, astnodes.Number) and is_potential_overflow(
            left_operand.n
        ):
            add_vulnerability(
                "Integer Overflow",
                "Potential integer overflow detected with left operand.",
                "overflow",
                "high",
                get_line_number(left_operand),
            )

        if isinstance(right_operand, astnodes.Number) and is_potential_overflow(
            right_operand.n
        ):
            add_vulnerability(
                "Integer Overflow",
                "Potential integer overflow detected with right operand.",
                "overflow",
                "high",
                get_line_number(right_operand),
            )

    if isinstance(node, astnodes.LocalAssign):
        for value in node.values:
            if isinstance(value, astnodes.Number) and is_potential_overflow(value.n):
                add_vulnerability(
                    "Integer Overflow",
                    "Potential integer overflow detected with local variable assignment.",
                    "overflow",
                    "high",
                    get_line_number(value),
                )

    if isinstance(node, astnodes.Function):
        for arg in node.args:
            if isinstance(arg, astnodes.Number) and is_potential_overflow(arg.n):
                add_vulnerability(
                    "Integer Overflow",
                    "Potential integer overflow detected with function argument.",
                    "overflow",
                    "high",
                    get_line_number(arg),
                )


def analyze_underflow_in_node(node):
    if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
        left_operand = node.left
        right_operand = node.right

        if isinstance(left_operand, astnodes.Number) and is_potential_underflow(
            left_operand.n
        ):
            add_vulnerability(
                "Integer Underflow",
                "Potential integer underflow detected with left operand.",
                "underflow",
                "high",
                get_line_number(left_operand),
            )

        if isinstance(right_operand, astnodes.Number) and is_potential_underflow(
            right_operand.n
        ):
            add_vulnerability(
                "Integer Underflow",
                "Potential integer underflow detected with right operand.",
                "underflow",
                "high",
                get_line_number(right_operand),
            )

    if isinstance(node, astnodes.LocalAssign):
        for value in node.values:
            if isinstance(value, astnodes.Number) and is_potential_underflow(value.n):
                add_vulnerability(
                    "Integer Underflow",
                    "Potential integer underflow detected with local variable assignment.",
                    "underflow",
                    "high",
                    get_line_number(value),
                )

    if isinstance(node, astnodes.Function):
        for arg in node.args:
            if isinstance(arg, astnodes.Number) and is_potential_underflow(arg.n):
                add_vulnerability(
                    "Integer Underflow",
                    "Potential integer underflow detected with function argument.",
                    "underflow",
                    "high",
                    get_line_number(arg),
                )


def analyze_overflow_and_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        analyze_overflow_in_node(node)

        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                analyze_overflow_in_node(body_node)

            if isinstance(node.name, astnodes.Name) and node.name.id == "another_example":
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(ret_val, astnodes.Number) and is_potential_overflow(ret_val.n):
                                add_vulnerability(
                                    "Integer Overflow",
                                    f"Potential integer overflow detected in return statement of function '{node.name.id}'.",
                                    "overflow",
                                    "high",
                                    get_line_number(ret_val),
                                )

def analyze_underflow_and_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        analyze_underflow_in_node(node)

        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                analyze_underflow_in_node(body_node)

            if isinstance(node.name, astnodes.Name) and node.name.id == "another_example":
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(ret_val, astnodes.Number) and is_potential_underflow(ret_val.n):
                                add_vulnerability(
                                    "Integer Underflow",
                                    f"Potential integer underflow detected in return statement of function '{node.name.id}'.",
                                    "underflow",
                                    "high",
                                    get_line_number(ret_val),)


def analyze_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            has_return = any(isinstance(n, astnodes.Return) for n in node.body.body)
            if not has_return:
                add_vulnerability(
                    "Missing Return Statement",
                    "A function is missing a return statement.",
                    "missing_return",
                    "low",
                    get_line_number(node),
                )


def check_private_key_exposure(code):
    tree = ast.parse(code)
    private_key_words = ["privatekey", "private_key", "secretkey", "secret_key", "keypair", "key_pair", "api_key", "clientsecret", "client_secret", "access_key", "arweave_key", "arweave_private_key", "arweave_secret", "arweave_wallet", "arweave_wallet_key", "arweave_wallet_private_key", "arweave_wallet_secret", "arweave_keyfile", "arweave_key_file", "arweave_keypair", "arweave_key_pair", "arweave_api_key", "arweave_client_secret", "arweave_access_key"]


    for node in ast.walk(tree):
        if isinstance(node, astnodes.Assign):
            for target in node.targets:
                if (
                    isinstance(target, astnodes.Name)
                    and target.id.lower() in private_key_words
                ):
                    add_vulnerability(
                        "Private Key Exposure",
                        f"Potential exposure of private key in variable '{target.id}'.",
                        "private_key_exposure",
                        "high",
                        get_line_number(node),
                    )


def analyze_reentrancy(code):
    tree = ast.parse(code)

    def is_external_call(node):
        return (
            isinstance(node, astnodes.Call)
            and isinstance(node.func, astnodes.Name)
            and node.func.id == "external_call"
        )

    def has_state_change(node):
        return isinstance(node, astnodes.Assign)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            body = node.body.body
            for i, n in enumerate(body):
                if is_external_call(n):
                    for subsequent_node in body[i + 1 :]:
                        if has_state_change(subsequent_node):
                            add_vulnerability(
                                "Reentrancy",
                                "A function calls an external contract before updating its state.",
                                "external_call",
                                "high",
                                get_line_number(node),
                            )


def analyze_floating_pragma(code):
    deprecated_functions = ["setfenv", "getfenv"]
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            if node.func.id in deprecated_functions:
                add_vulnerability(
                    "Floating Pragma",
                    f"Floating pragma issue detected with function '{node.func.id}'.",
                    "floating_pragma",
                    "low",
                    get_line_number(node),
                )


def analyze_denial_of_service(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            if node.func.id == "perform_expensive_operation":
                add_vulnerability(
                    "Denial of Service",
                    f"Potential Denial of Service vulnerability detected with function '{node.func.id}'.",
                    "denial_of_service",
                    "medium",
                    get_line_number(node),
                )


def analyze_unchecked_external_calls(code):
    tree = ast.parse(code)

    def is_external_call(node):
        # Handle both simple names (Name) and indexed names (Index)
        if isinstance(node, astnodes.Call):
            if isinstance(node.func, astnodes.Name):
                return node.func.id in ["external_call", "SmartWeave.call", "ao.send"]
            elif isinstance(node.func, astnodes.Index):
                # Handle cases like table["method"]()
                if isinstance(node.func.value, astnodes.Name):
                    return node.func.value.id in ["external", "contract"]
        return False

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            # Get function name safely
            func_name = "anonymous"
            if isinstance(node.name, astnodes.Name):
                func_name = node.name.id
            elif isinstance(node.name, astnodes.Index):
                # Handle cases where function name is indexed
                func_name = str(node.name)  # Or extract specific parts as needed

            for n in node.body.body:
                if is_external_call(n):
                    add_vulnerability(
                        "Unchecked External Calls",
                        f"Unchecked external call detected in function '{func_name}'.",
                        "unchecked_external_call",
                        "medium",
                        get_line_number(n),
                    )

def analyze_greedy_suicidal_functions(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            for n in node.body.body:
                if (
                    isinstance(n, astnodes.Call)
                    and isinstance(n.func, astnodes.Name)
                    and n.func.id == "transfer_funds"
                ):
                    if not any(
                        isinstance(subsequent_node, astnodes.Return)
                        for subsequent_node in node.body.body
                    ):
                        add_vulnerability(
                            "Greedy Function",
                            f"Greedy function detected without a return statement in function '{node.name.id}'.",
                            "greedy_function",
                            "high",
                            get_line_number(n),
                        )
def get_code_and_vulnerable_lines(code, vulnerabilities):
    # Total lines
    total_lines = len(code.splitlines())
    
    # Vulnerable lines (extract unique line numbers from vulnerabilities)
    vulnerable_lines = {vuln["line"] for vuln in vulnerabilities if "line" in vuln}
    num_vulnerable_lines = len(vulnerable_lines)
    
    return total_lines, num_vulnerable_lines

# new function to analyze lua code

def analyze_access_control(code):
    """
    Analyzes Lua code for access control issues, particularly in sensitive functions like mint and burn.
    """
    tree = ast.parse(code)

    def has_access_control(node):
        """
        Check if the node contains access control logic, e.g., checking owner or caller.
        """
        if isinstance(node, astnodes.If):
            for condition in ast.walk(node.test):
                if isinstance(condition, astnodes.Name) and condition.id in ["owner", "caller"]:
                    return True
        return False

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            function_name = node.name.id if isinstance(node.name, astnodes.Name) else None
            if function_name in ["mint", "burn"]:
                access_control_found = False
                for body_node in ast.walk(node.body):
                    if has_access_control(body_node):
                        access_control_found = True
                        break
                if not access_control_found:
                    severity = "high" if function_name in ["mint", "burn"] else "medium"
                    add_vulnerability(
                        "Access Control Issue",
                        f"Missing access control check in sensitive function '{function_name}'.",
                        "access_control",
                        severity,
                        get_line_number(node),
                    )

def is_critical_state_change(node):
    return (
        isinstance(node, astnodes.Assign)
        or (
            isinstance(node, astnodes.Call)
            and isinstance(node.func, astnodes.Name)
            and node.func.id.lower() in ["mint", "burn", "transfer"]
        )
    )
def is_error_handling_missing(node):
    has_error_handling = any(
        isinstance(stmt, astnodes.TryExcept) or isinstance(stmt, astnodes.PCall)
        for stmt in node.body.body
    )
    return not has_error_handling

def analyze_unhandled_errors_in_handlers(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            if isinstance(node.name, astnodes.Name) and node.name.id == "another_example":
                body = node.body.body
                for stmt in body:
                    if is_critical_state_change(stmt) and is_error_handling_missing(node):
                        add_vulnerability(
                            "Unhandled Errors in Handlers",
                            f"Unhandled errors in function '{node.name.id}' where critical state changes occur.",
                            "unhandled_errors",
                            "high",
                            get_line_number(stmt),
                        )


def analyze_reentrancy_in_handlers(code):
    tree = ast.parse(code)

    def is_state_change(node):
        return isinstance(node, astnodes.Assign) or (
            isinstance(node, astnodes.Call) and node.func.id.lower() in ["mint", "burn"]
        )

    def is_external_call(node):
        # Check if the node is a Call node
        if isinstance(node, astnodes.Call):
            # If the function is a simple Name node (e.g., msg.reply or ao.send)
            if isinstance(node.func, astnodes.Name):
                return node.func.id.lower() in ["msg.reply", "ao.send"]
            # If the function is an Index node (e.g., obj["key"])
            elif isinstance(node.func, astnodes.Index):
                # Check if the value part of the index is a Name node
                if isinstance(node.func.value, astnodes.Name):
                    return node.func.value.id.lower() in ["msg.reply", "ao.send"]
        return False

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            body = node.body.body
            for i, stmt in enumerate(body):
                if is_external_call(stmt):
                    for subsequent_node in body[i + 1:]:
                        if is_state_change(subsequent_node):
                            add_vulnerability(
                                "Reentrancy in Handlers",
                                f"Reentrancy vulnerability in function '{node.name.id}' where state changes follow external calls.",
                                "reentrancy",
                                "high",
                                get_line_number(stmt),
                            )




def analyze_improper_balance_checks(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            # Check for improper usage of balance operations
            if node.func.id in ["add", "subtract"]:
                args = node.args
                if len(args) == 2 and all(isinstance(arg, astnodes.Name) for arg in args):
                    if any(
                        arg.id.lower() in ["balances[msg.from]", "balances[msg.recipient]"]
                        for arg in args
                    ):
                        add_vulnerability(
                            "Improper Balance Checks",
                            f"Potential improper balance check in function '{node.func.id}'.",
                            "improper_balance_check",
                            "high",
                            get_line_number(node),
                        )

            # Check for negative balances or improper handling
            if (
                node.func.id in ["add", "subtract"]
                and any(isinstance(arg, astnodes.Number) and arg.n < 0 for arg in node.args)
            ):
                add_vulnerability(
                    "Negative Balances",
                    "Negative balance detected in a critical operation.",
                    "negative_balance",
                    "medium",
                    get_line_number(node),
                )

def analyze_replay_attacks(code):
    """
    Analyzes Lua code to detect replay attack vulnerabilities.
    Checks for missing unique tracking mechanisms (msg.Id or timestamps)
    and the absence of history verification for processed requests.
    """
    tree = ast.parse(code)

    has_processed_table = False
    has_replay_protection = False

    for node in ast.walk(tree):
        if (
            isinstance(node, astnodes.Assign)
            and isinstance(node.targets[0], astnodes.Name)
            and node.targets[0].id.lower() in ["processed_messages", "processed_ids"]
        ):
            has_processed_table = True

        if (
            isinstance(node, astnodes.If)
            and isinstance(node.test, astnodes.Index)
            and isinstance(node.test.value, astnodes.Name)
            and node.test.value.id.lower() in ["processed_messages", "processed_ids"]
        ):
            if isinstance(node.test.idx, astnodes.Name) and node.test.idx.id == "msg.Id":
                has_replay_protection = True

    if not has_processed_table:
        add_vulnerability(
            "Replay Attack",
            "No processed message table (e.g., processedMessages) to track processed requests.",
            "replay_attack",
            "high",
            0,  
        )

    if has_processed_table and not has_replay_protection:
        add_vulnerability(
            "Replay Attack",
            "Processed table exists but lacks replay protection mechanism for msg.Id.",
            "replay_attack",
            "medium",
            0,  
        )



def analyze_state_reset_misuse(code):
    """
    Analyzes Lua code for misuse of the ResetState flag.
    Detects:
    1. Unrestricted access to ResetState.
    2. Arbitrary toggling of ResetState in production.
    """
    tree = ast.parse(code)
    vulnerabilities = []

    for node in ast.walk(tree):
        if isinstance(node, Assign) and any(
            isinstance(target, Name) and target.id == "ResetState"
            for target in node.targets
        ):
            if not any(
                isinstance(parent, If)
                and any(
                    isinstance(cond, Name) and cond.id in ["isAdmin", "isTrusted"]
                    for cond in ast.walk(parent.test)
                )
                for parent in ast.walk(tree)
            ):
                vulnerabilities.append({
                    "type": "State Reset Misuse",
                    "message": "ResetState is toggled without access control.",
                    "severity": "high",
                    "line": getattr(node, "lineno", None),
                })

        if isinstance(node, Call) and isinstance(node.func, Name) and node.func.id == "resetBalances":
            if not any(
                isinstance(parent, If)
                and any(
                    isinstance(cond, Name) and cond.id in ["isTrusted", "isAdmin"]
                    for cond in ast.walk(parent.test)
                )
                for parent in ast.walk(tree)
            ):
                vulnerabilities.append({
                    "type": "Critical State Reset",
                    "message": "Critical reset operation performed without safeguard.",
                    "severity": "medium",
                    "line": getattr(node, "lineno", None),
                })

    return vulnerabilities


def analyze_tag_handling_security(code):
    """
    Analyzes Lua code to detect vulnerabilities in tag handling.
    Specifically checks for:
    1. Overwriting of critical keys by tags starting with "X-".
    2. Lack of sanitization or validation of tags starting with "X-".
    """
    if not code.strip():
        raise ValueError("Lua code is empty or invalid.")
    
    try:
        tree = ast.parse(code)
    except luaparser.builder.SyntaxException as e:
        raise ValueError(f"Syntax error while parsing Lua code: {str(e)}")

    vulnerabilities = []

    critical_keys = ["userData", "session", "config", "admin"]

    for node in ast.walk(tree):
        if isinstance(node, Assign):
            for target in node.targets:
                if isinstance(target, Index) and isinstance(target.idx, String):
                    tag_name = target.idx.s
                    if tag_name.startswith("X-"):  
                        if any(critical_key in tag_name for critical_key in critical_keys):
                            vulnerabilities.append({
                                "type": "Tag Handling Security",
                                "message": f"Tag '{tag_name}' starts with 'X-' and may overwrite a critical key.",
                                "severity": "high",
                                "line": getattr(node, "lineno", None),
                            })

                        if not any(
                            isinstance(stmt, Call) and isinstance(stmt.func, Name) and stmt.func.id == "sanitizeTag"
                            for stmt in ast.walk(tree)
                        ):
                            vulnerabilities.append({
                                "type": "Tag Handling Security",
                                "message": f"Tag '{tag_name}' starting with 'X-' is not sanitized.",
                                "severity": "high",
                                "line": getattr(node, "lineno", None),
                            })
    
    return vulnerabilities

def analyze_arithmetic(tree):
    """Check for overflows/underflows in token math."""
    for node in ast.walk(tree):
        if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
            left = node.left
            right = node.right
            
            # Check for literal overflows
            if isinstance(left, astnodes.Number) and abs(left.n) > 1e18:
                add_vulnerability(
                    "Integer Overflow",
                    f"Large literal number may overflow: {left.n}",
                    "arithmetic",
                    "high",
                    get_line_number(left)
                )
            
            # Check for division by zero
            if isinstance(node, astnodes.DivOp) and (
                (isinstance(right, astnodes.Number) and right.n == 0) or
                (isinstance(right, astnodes.Name) and "balance" in right.id)
            ):
                add_vulnerability(
                    "Division by Zero",
                    "Potential division by zero in arithmetic operation.",
                    "arithmetic",
                    "critical",
                    get_line_number(node)
                )

def analyze_frontrunning(tree):
    """Check for transactions susceptible to front-running."""
    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            if node.func.id in ["swap", "add_liquidity"]:
                if not has_slippage_control(node):
                    add_vulnerability(
                        "Front-Running",
                        "Missing slippage control in swap/addLiquidity.",
                        "frontrunning",
                        "medium",
                        get_line_number(node)
                    )


def analyze_oracle_manipulation(tree):
    """Detect unsafe price feed usage."""
    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            if node.func.id in ["get_price", "calculate_value"]:
                if not has_multiple_oracles(node):
                    add_vulnerability(
                        "Oracle Manipulation",
                        "Single-point oracle usage (manipulation risk).",
                        "oracle",
                        "high",
                        get_line_number(node)
                    )

def analyze_flash_loans(tree):
    """Check for flash loan attack vectors."""
    for node in ast.walk(tree):
        if isinstance(node, astnodes.If):
            if is_balance_check(node.test) and not has_reentrancy_guard(node):
                add_vulnerability(
                    "Flash Loan Risk",
                    "Unprotected balance check (flash loan attack possible).",
                    "high",
                    get_line_number(node)
                )


def emits_event(node):
    """Check if a function emits events for state changes."""
    # Look for event emission patterns
    for stmt in ast.walk(node):
        if isinstance(stmt, astnodes.Call) and isinstance(stmt.func, astnodes.Name):
            if stmt.func.id in ['emit', 'log', 'event']:
                return True
    return False


def analyze_event_logging(tree):
    """Ensure critical actions are logged."""
    critical_functions = ["transfer", "mint", "burn"]
    
    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            func_name = node.name.id if isinstance(node.name, astnodes.Name) else None
            
            if func_name in critical_functions:
                if not emits_event(node):
                    add_vulnerability(
                        "Silent State Change",
                        f"Critical function '{func_name}' lacks event logging.",
                        "event_logging",
                        "medium",
                        get_line_number(node)
                    )


def find_parent_function(node):
    """Navigate up AST to find enclosing function."""
    while hasattr(node, "_parent"):
        node = node._parent
        if isinstance(node, astnodes.Function):
            return node
    return None

def has_state_change_after(func_node, target_node):
    """Check if state is modified after a target node."""
    found_target = False
    for child in ast.walk(func_node.body):
        if child == target_node:
            found_target = True
        elif found_target and isinstance(child, (astnodes.Assign, astnodes.Call)):
            return True
    return False

def has_access_control(node):
    """Check for owner/caller checks in function."""
    for child in ast.walk(node.body):
        if isinstance(child, astnodes.If):
            if "msg.sender" in ast.dump(child.test) or "owner" in ast.dump(child.test):
                return True
    return False
                    

def analyze_lua_code(code):
    global vulnerabilities
    vulnerabilities = []
    
    try:
        tree = ast.parse(code)
        
        # Pass tree to functions that expect it
        analyze_arithmetic(tree)
        analyze_flash_loans(tree)
        analyze_oracle_manipulation(tree)
        analyze_frontrunning(tree)
        analyze_event_logging(tree)
        
        # Pass code to functions that expect raw code
        analyze_tag_handling_security(code)
        analyze_state_reset_misuse(code)
        analyze_replay_attacks(code)
        analyze_improper_balance_checks(code)
        analyze_reentrancy_in_handlers(code)
        analyze_unhandled_errors_in_handlers(code)
        analyze_access_control(code)
        analyze_overflow_and_return(code)
        analyze_underflow_and_return(code)
        analyze_return(code)
        check_private_key_exposure(code)
        analyze_reentrancy(code)
        analyze_floating_pragma(code)
        analyze_denial_of_service(code)
        analyze_unchecked_external_calls(code)
        analyze_greedy_suicidal_functions(code)
        
    except Exception as e:
        add_vulnerability(
            "Parse Error",
            f"Failed to parse Lua code: {str(e)}",
            "parse_error",
            "medium",
            1
        )
    
    return vulnerabilities



@app.route("/analyze", methods=["POST"])
def analyze():
    code = request.form.get("code")
    if not code:
        return "No code provided", 400

    vulnerabilities = analyze_lua_code(code)
    total_lines, num_vulnerable_lines = get_code_and_vulnerable_lines(code, vulnerabilities)

    # Check if any vulnerabilities were found
    # if not vulnerabilities:
    #     return jsonify({"message": "No vulnerabilities found."}), 200
    
    # return jsonify(vulnerabilities)
    if not vulnerabilities:
        return jsonify({
            "message": "No vulnerabilities found.",
            "total_lines": total_lines,
            "vulnerable_lines": num_vulnerable_lines
        })
    
    return jsonify({
        "vulnerabilities": vulnerabilities,
        "total_lines": total_lines,
        "vulnerable_lines": num_vulnerable_lines
    })

# ============================================================================
# AI AGENT ENDPOINTS
# ============================================================================

@app.route("/ai/analyze", methods=["POST"])
def ai_analyze():
    """Enhanced analysis with AI-powered insights and remediation suggestions"""
    try:
        code = request.json.get("code", "")
        if not code:
            return jsonify({"error": "No code provided"}), 400
        
        # Initialize AI agent
        security_agent = create_security_agent()
        
        # Perform traditional vulnerability analysis
        global vulnerabilities
        vulnerabilities = []
        traditional_vulns = analyze_lua_code(code)
        total_lines, num_vulnerable_lines = get_code_and_vulnerable_lines(code, traditional_vulns)
        
        # Get AI-powered overall analysis
        ai_analysis = security_agent.analyze_code_with_ai(code)
        
        # Generate fix suggestions for each vulnerability
        enhanced_vulnerabilities = []
        for vuln in traditional_vulns:
            # Get code context around the vulnerability
            code_lines = code.split('\n')
            line_num = vuln.get('line', 1)
            
            # Extract context (5 lines before and after)
            start_line = max(0, line_num - 6)
            end_line = min(len(code_lines), line_num + 5)
            context = '\n'.join(code_lines[start_line:end_line])
            
            # Generate AI fix suggestion
            fix_suggestion = security_agent.generate_fix_suggestion(vuln, context, line_num)
            
            # Generate explanation
            explanation = security_agent.explain_vulnerability(vuln, context)
            
            # Enhance vulnerability with AI insights
            enhanced_vuln = {
                **vuln,
                "ai_fix": fix_suggestion,
                "ai_explanation": explanation,
                "code_context": context,
                "context_lines": {
                    "start": start_line + 1,
                    "end": end_line
                }
            }
            enhanced_vulnerabilities.append(enhanced_vuln)
        
        response = {
            "vulnerabilities": enhanced_vulnerabilities,
            "total_lines": total_lines,
            "vulnerable_lines": num_vulnerable_lines,
            "ai_analysis": ai_analysis,
            "agent_version": "1.0.0",
            "enhanced": True
        }
        
        if not enhanced_vulnerabilities:
            response["message"] = "No vulnerabilities found."
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            "error": f"AI analysis failed: {str(e)}",
            "fallback_message": "Please try the regular analysis endpoint"
        }), 500

@app.route("/ai/fix", methods=["POST"])
def ai_fix_suggestion():
    """Get AI-powered fix suggestions for specific vulnerability"""
    try:
        data = request.json
        vulnerability = data.get("vulnerability", {})
        code_context = data.get("code_context", "")
        line_number = data.get("line_number")
        
        if not vulnerability or not code_context:
            return jsonify({"error": "Missing vulnerability or code context"}), 400
        
        # Initialize AI agent
        security_agent = create_security_agent()
        
        # Generate fix suggestion
        fix_suggestion = security_agent.generate_fix_suggestion(
            vulnerability, code_context, line_number
        )
        
        return jsonify({
            "fix_suggestion": fix_suggestion,
            "vulnerability": vulnerability,
            "timestamp": "2025-07-09"
        })
        
    except Exception as e:
        return jsonify({"error": f"Fix generation failed: {str(e)}"}), 500

@app.route("/ai/explain", methods=["POST"])
def ai_explain():
    """Get detailed explanation of vulnerability"""
    try:
        data = request.json
        vulnerability = data.get("vulnerability", {})
        code_context = data.get("code_context", "")
        
        if not vulnerability or not code_context:
            return jsonify({"error": "Missing vulnerability or code context"}), 400
        
        # Initialize AI agent
        security_agent = create_security_agent()
        
        # Generate explanation
        explanation = security_agent.explain_vulnerability(vulnerability, code_context)
        
        return jsonify({
            "explanation": explanation,
            "vulnerability": vulnerability,
            "timestamp": "2025-07-09"
        })
        
    except Exception as e:
        return jsonify({"error": f"Explanation generation failed: {str(e)}"}), 500

@app.route("/ai/chat", methods=["POST"])
def ai_chat():
    """Interactive chat with security expert AI"""
    try:
        data = request.json
        message = data.get("message", "")
        code_context = data.get("code_context")
        
        if not message:
            return jsonify({"error": "No message provided"}), 400
        
        # Initialize chat agent
        chat_agent = create_chat_agent()
        
        # Get response
        response = chat_agent.chat(message, code_context)
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({"error": f"Chat failed: {str(e)}"}), 500

# ============================================================================
# END AI AGENT ENDPOINTS
# ============================================================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/ai')
def ai_agent():
    """AI Agent enhanced interface"""
    return render_template('ai_agent.html')

@app.route("/analyzecells", methods=["POST"])
def analyze_cells():
    code_cells = request.json.get("code_cells", [])
    results = []

    for cell in code_cells:
        cell_vulnerabilities = []
        global vulnerabilities
        vulnerabilities = []

        try:
            analyze_overflow_and_return(cell)
            analyze_underflow_and_return(cell)
            analyze_return(cell)
            check_private_key_exposure(cell)
            analyze_reentrancy(cell)
            analyze_floating_pragma(cell)
            analyze_denial_of_service(cell)
            analyze_unchecked_external_calls(cell)
            analyze_greedy_suicidal_functions(cell)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        if vulnerabilities:
            cell_vulnerabilities.extend(vulnerabilities)

        results.append({"code_cell": cell, "vulnerabilities": cell_vulnerabilities})

    return jsonify(results)


@app.route("/cells")
def cells():
    return render_template("cells.html")


# ============================================================================
# LEARNING AGENT ENDPOINTS
# ============================================================================

@app.route("/learning/stats", methods=["GET"])
def learning_stats():
    """Get learning agent statistics"""
    try:
        learning_agent = create_learning_agent()
        stats = learning_agent.get_learning_stats()
        suggestions = learning_agent.suggest_improvements()
        
        return jsonify({
            "stats": stats,
            "suggestions": suggestions,
            "timestamp": "2025-07-09"
        })
    except Exception as e:
        return jsonify({"error": f"Failed to get learning stats: {str(e)}"}), 500

@app.route("/learning/feedback", methods=["POST"])
def submit_feedback():
    """Submit feedback for learning improvement"""
    try:
        data = request.json
        vulnerability_id = data.get("vulnerability_id")
        feedback = data.get("feedback")
        is_correct = data.get("is_correct", True)
        user_comment = data.get("user_comment")
        
        learning_agent = create_learning_agent()
        learning_agent.record_feedback(vulnerability_id, feedback, is_correct, user_comment)
        learning_agent.save_patterns()
        
        return jsonify({
            "message": "Feedback recorded successfully",
            "feedback_id": vulnerability_id
        })
    except Exception as e:
        return jsonify({"error": f"Failed to record feedback: {str(e)}"}), 500

@app.route("/learning/train", methods=["POST"])
def train_learning_agent():
    """Train the learning agent with vulnerability data"""
    try:
        data = request.json
        code_snippet = data.get("code_snippet", "")
        vulnerability = data.get("vulnerability", {})
        user_feedback = data.get("user_feedback")
        
        if not code_snippet or not vulnerability:
            return jsonify({"error": "Missing code snippet or vulnerability data"}), 400
        
        learning_agent = create_learning_agent()
        learned = learning_agent.learn_from_vulnerability(code_snippet, vulnerability, user_feedback)
        learning_agent.save_patterns()
        
        return jsonify({
            "learned": learned,
            "message": "New pattern learned" if learned else "Pattern updated",
            "total_patterns": len(learning_agent.patterns)
        })
    except Exception as e:
        return jsonify({"error": f"Training failed: {str(e)}"}), 500

@app.route("/learning/analyze", methods=["POST"])
def learning_analyze():
    """Enhanced analysis using learned patterns with auto-learning"""
    try:
        data = request.json
        code = data.get("code", "")
        enable_auto_learning = data.get("auto_learn", True)
        
        if not code:
            return jsonify({"error": "No code provided"}), 400
        
        learning_agent = create_learning_agent()
        
        # Check against learned patterns first
        learned_matches = learning_agent.check_against_learned_patterns(code)
        
        # Run traditional analysis for comparison and learning
        global vulnerabilities
        vulnerabilities = []
        traditional_vulns = analyze_lua_code(code)
        
        # Auto-learn from analysis results
        learning_summary = {}
        if enable_auto_learning and traditional_vulns:
            learning_summary = learning_agent.auto_learn_from_analysis(code, traditional_vulns)
        
        # Validate patterns periodically (every 50 patterns)
        validation_report = {}
        if len(learning_agent.patterns) % 50 == 0 and len(learning_agent.patterns) > 0:
            validation_report = learning_agent.validate_patterns()
        
        # Get learning recommendations
        recommendations = learning_agent.get_learning_recommendations()
        
        # Enhanced learning stats
        learning_stats = learning_agent.get_learning_stats()
        
        learning_agent.save_patterns()
        
        response_data = {
            "learned_patterns": learned_matches,
            "traditional_vulnerabilities": traditional_vulns,
            "learning_stats": learning_stats,
            "auto_learning_summary": learning_summary,
            "learning_recommendations": recommendations,
            "analysis_metadata": {
                "total_patterns_checked": len(learned_matches),
                "traditional_vulns_found": len(traditional_vulns),
                "code_length": len(code),
                "auto_learning_enabled": enable_auto_learning,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        # Include validation report if available
        if validation_report:
            response_data["validation_report"] = validation_report
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({"error": f"Enhanced learning analysis failed: {str(e)}"}), 500

@app.route("/learning/export", methods=["GET"])
def export_patterns():
    """Export learned patterns"""
    try:
        learning_agent = create_learning_agent()
        export_file = learning_agent.export_patterns()
        
        return jsonify({
            "message": "Patterns exported successfully",
            "export_file": export_file,
            "total_patterns": len(learning_agent.patterns)
        })
    except Exception as e:
        return jsonify({"error": f"Export failed: {str(e)}"}), 500

@app.route("/learning/validate", methods=["POST"])
def validate_learning_patterns():
    """Validate and clean up learning patterns"""
    try:
        learning_agent = create_learning_agent()
        validation_report = learning_agent.validate_patterns()
        learning_agent.save_patterns()
        
        return jsonify({
            "validation_report": validation_report,
            "updated_stats": learning_agent.get_learning_stats()
        })
    except Exception as e:
        return jsonify({"error": f"Pattern validation failed: {str(e)}"}), 500

@app.route("/learning/recommendations", methods=["GET"])
def get_learning_recommendations():
    """Get learning recommendations for improving the AI agent"""
    try:
        learning_agent = create_learning_agent()
        recommendations = learning_agent.get_learning_recommendations()
        stats = learning_agent.get_learning_stats()
        
        return jsonify({
            "recommendations": recommendations,
            "learning_stats": stats,
            "insights": stats.get("learning_insights", [])
        })
    except Exception as e:
        return jsonify({"error": f"Failed to get recommendations: {str(e)}"}), 500

@app.route("/learning/dashboard", methods=["GET"])
def learning_dashboard():
    """Get comprehensive learning dashboard data"""
    try:
        learning_agent = create_learning_agent()
        stats = learning_agent.get_learning_stats()
        recommendations = learning_agent.get_learning_recommendations()
        
        # Calculate additional dashboard metrics
        dashboard_data = {
            "overview": {
                "total_patterns": stats.get("total_patterns", 0),
                "average_accuracy": round(stats.get("average_accuracy", 0), 3),
                "average_confidence": round(stats.get("average_confidence", 0), 3),
                "learning_health": "Excellent" if stats.get("average_accuracy", 0) > 0.8 else 
                                 "Good" if stats.get("average_accuracy", 0) > 0.6 else 
                                 "Needs Improvement"
            },
            "vulnerability_analysis": stats.get("vulnerability_analysis", {}),
            "top_performers": stats.get("top_performing_patterns", []),
            "learning_insights": stats.get("learning_insights", []),
            "recommendations": recommendations,
            "cache_performance": stats.get("cache_stats", {}),
            "learning_metadata": stats.get("learning_metadata", {}),
            "patterns_by_type": stats.get("patterns_by_type", {}),
            "vulnerability_weights": stats.get("vulnerability_weights", {})
        }
        
        return jsonify(dashboard_data)
    except Exception as e:
        return jsonify({"error": f"Dashboard data failed: {str(e)}"}), 500

# Helper functions for vulnerability detection
def has_slippage_control(node):
    """Check if a swap/liquidity function has slippage protection."""
    # Look for slippage-related parameters or conditions
    if hasattr(node, 'args'):
        for arg in node.args:
            if isinstance(arg, astnodes.Name) and 'slippage' in arg.id.lower():
                return True
    return False

def has_multiple_oracles(node):
    """Check if oracle calls use multiple price feeds."""
    # Look for multiple oracle sources or aggregation
    if hasattr(node, 'args'):
        oracle_count = 0
        for arg in node.args:
            if isinstance(arg, astnodes.Name) and 'oracle' in arg.id.lower():
                oracle_count += 1
        return oracle_count > 1
    return False

def is_balance_check(node):
    """Check if a condition involves balance checking."""
    if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
        return node.func.id in ['balance', 'get_balance', 'balanceOf']
    return False

def has_reentrancy_guard(node):
    """Check if a function has reentrancy protection."""
    # Look for reentrancy guard patterns
    current = node
    while hasattr(current, '_parent'):
        current = current._parent
        if isinstance(current, astnodes.Function):
            # Check for guard variables or modifiers
            for stmt in ast.walk(current):
                if isinstance(stmt, astnodes.LocalAssign):
                    for target in stmt.targets:
                        if isinstance(target, astnodes.Name) and 'guard' in target.id.lower():
                            return True
            break
    return False

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
