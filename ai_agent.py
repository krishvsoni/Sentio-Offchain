# ------------------------------------------------------------------------------
# AI Agent Module for Lua Security Analyzer
# Project: Offchain Analyzer - AI Agent
# Author: Sentio Team
# Email: connectsentio@gmail.com
# Date Published: 2025-07-9
# Description: AI-powered remediation agent using Google Gemini API for 
#              intelligent vulnerability fix suggestions and security analysis.
# ------------------------------------------------------------------------------

import google.generativeai as genai
import os
from dotenv import load_dotenv
import json
import re
from typing import Dict, List, Optional, Tuple

# Load environment variables
load_dotenv()

class SecurityAgent:
    """AI Agent for security analysis and remediation suggestions"""
    
    def __init__(self):
        """Initialize the Security Agent with Gemini API"""
        self.api_key = os.getenv('AGENT_API_KEY')
        if not self.api_key:
            raise ValueError("AGENT_API_KEY not found in environment variables")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Vulnerability knowledge base
        self.vulnerability_patterns = {
            "Integer Overflow": {
                "description": "Arithmetic operations that can exceed integer limits",
                "common_fixes": ["Add bounds checking", "Use safe math libraries", "Validate input ranges"]
            },
            "Integer Underflow": {
                "description": "Arithmetic operations that can go below minimum integer value",
                "common_fixes": ["Add lower bounds checking", "Validate negative operations"]
            },
            "Reentrancy": {
                "description": "Functions that can be called recursively before completion",
                "common_fixes": ["Use checks-effects-interactions pattern", "Add reentrancy guards", "State changes before external calls"]
            },
            "Private Key Exposure": {
                "description": "Hardcoded private keys or sensitive data in code",
                "common_fixes": ["Use environment variables", "Implement secure key management", "Remove hardcoded secrets"]
            },
            "Denial of Service": {
                "description": "Code patterns that can cause service unavailability",
                "common_fixes": ["Add gas limits", "Implement rate limiting", "Add circuit breakers"]
            },
            "Unchecked External Calls": {
                "description": "External function calls without proper error handling",
                "common_fixes": ["Add return value checks", "Implement proper error handling", "Use try-catch patterns"]
            },
            "Greedy/Suicidal Functions": {
                "description": "Functions that can drain resources or destroy contracts",
                "common_fixes": ["Add access controls", "Implement withdrawal patterns", "Add multi-sig requirements"]
            }
        }

    def generate_fix_suggestion(self, vulnerability: Dict, code_context: str, line_number: int = None) -> Dict:
        """
        Generate intelligent fix suggestions for detected vulnerabilities
        
        Args:
            vulnerability: Dictionary containing vulnerability details
            code_context: The relevant code snippet around the vulnerability
            line_number: Line number where vulnerability was detected
            
        Returns:
            Dictionary with fix suggestions, explanations, and secure code examples
        """
        
        vulnerability_name = vulnerability.get('name', 'Unknown')
        vulnerability_desc = vulnerability.get('description', '')
        severity = vulnerability.get('severity', 'medium')
        
        prompt = self._build_remediation_prompt(
            vulnerability_name, vulnerability_desc, code_context, line_number, severity
        )
        
        try:
            response = self.model.generate_content(prompt)
            fix_suggestion = self._parse_ai_response(response.text)
            
            # Enhance with knowledge base
            if vulnerability_name in self.vulnerability_patterns:
                pattern_info = self.vulnerability_patterns[vulnerability_name]
                fix_suggestion['common_fixes'] = pattern_info['common_fixes']
                fix_suggestion['pattern_description'] = pattern_info['description']
            
            return fix_suggestion
            
        except Exception as e:
            return {
                "error": f"Failed to generate fix suggestion: {str(e)}",
                "explanation": "Please try again or contact support",
                "fixed_code": None,
                "confidence": 0
            }

    def analyze_code_with_ai(self, code: str) -> Dict:
        """
        Perform AI-powered security analysis of Lua code
        
        Args:
            code: Lua code to analyze
            
        Returns:
            Dictionary with AI insights, risk assessment, and recommendations
        """
        
        prompt = f"""
        As a security expert, analyze this Lua smart contract code for potential vulnerabilities and security risks:

        ```lua
        {code}
        ```

        Please provide:
        1. Overall security risk assessment (Low/Medium/High)
        2. Key security concerns identified
        3. Best practices recommendations
        4. Code quality insights
        5. Gas optimization suggestions (if applicable)

        Format your response as a structured analysis with clear sections.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return {
                "ai_analysis": response.text,
                "timestamp": "2025-07-09",
                "model": "gemini-1.5-flash"
            }
        except Exception as e:
            return {
                "error": f"AI analysis failed: {str(e)}",
                "ai_analysis": "Analysis unavailable"
            }

    def explain_vulnerability(self, vulnerability: Dict, code_context: str) -> str:
        """
        Generate human-readable explanation of why code is vulnerable
        
        Args:
            vulnerability: Vulnerability details
            code_context: Code snippet
            
        Returns:
            Detailed explanation string
        """
        
        vulnerability_name = vulnerability.get('name', 'Unknown')
        
        prompt = f"""
        You are a security educator explaining Lua smart contract vulnerabilities.
        
        **VULNERABILITY:** {vulnerability_name}
        **DETECTED IN CODE:**
        ```lua
        {code_context}
        ```
        
        **VULNERABILITY DETAILS:** {vulnerability.get('description', '')}
        
        Provide a comprehensive, educational explanation following this structure:
        
        ## 🔍 What is {vulnerability_name}?
        
        [Clear definition in simple terms]
        
        ## ⚠️ Why is this dangerous?
        
        **Immediate risks:**
        - [Risk 1]
        - [Risk 2]
        
        **Potential attack scenarios:**
        1. [Scenario 1 with steps]
        2. [Scenario 2 with steps]
        
        ## 💥 What could go wrong?
        
        **For users:** [Impact description]
        **For the system:** [Impact description]
        **Financial impact:** [Economic consequences]
        
        ## 🛡️ How to identify this vulnerability
        
        **Code patterns to watch for:**
        - [Pattern 1]
        - [Pattern 2]
        
        ## 📚 Real-world examples
        
        [Brief mention of similar vulnerabilities or attacks if applicable]
        
        Keep explanations:
        - Educational and approachable
        - Focused on practical understanding
        - Specific to the code provided
        - Clear about consequences and risks
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"""
            ## ⚠️ Explanation Unavailable
            
            I'm having trouble generating a detailed explanation right now.
            
            **Basic Info:**
            - **Vulnerability:** {vulnerability_name}
            - **Description:** {vulnerability.get('description', 'No description available')}
            - **Severity:** {vulnerability.get('severity', 'Unknown')}
            
            **Error:** {str(e)}
            
            Please try again or consult security documentation for more details about {vulnerability_name}.
            """

    def _build_remediation_prompt(self, vuln_name: str, vuln_desc: str, code: str, 
                                line_number: int, severity: str) -> str:
        """Build the prompt for fix suggestion generation"""
        
        prompt = f"""
        You are a security expert specializing in Lua smart contract security. 
        
        **VULNERABILITY DETECTED:**
        - **Type:** {vuln_name}
        - **Description:** {vuln_desc}
        - **Severity:** {severity}
        - **Line:** {line_number if line_number else 'Unknown'}

        **VULNERABLE CODE:**
        ```lua
        {code}
        ```

        Please provide a comprehensive security analysis and fix suggestion.
        
        **Required Response Format (JSON):**
        ```json
        {{
            "explanation": "Detailed explanation of why this code is vulnerable. Include what could go wrong and potential attack scenarios.",
            "fixed_code": "Complete secure version of the code with proper safeguards",
            "reasoning": "Step-by-step explanation of why your fix addresses the vulnerability and prevents attacks",
            "confidence": 8,
            "additional_notes": "Any other security considerations, best practices, or related vulnerabilities to watch for",
            "prevention_tips": [
                "Specific tip 1 to prevent this vulnerability",
                "Specific tip 2 for better security"
            ]
        }}
        ```

        **Guidelines:**
        - Explain vulnerabilities in simple terms
        - Provide complete, working secure code
        - Include specific prevention strategies
        - Rate confidence honestly (1-10 scale)
        - Focus on practical, implementable solutions
        - Consider edge cases and related security issues
        """
        
        return prompt

    def _parse_ai_response(self, response_text: str) -> Dict:
        """Parse AI response and extract structured information"""
        
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                return json.loads(json_str)
        except:
            pass
        
        # Fallback: parse manually
        return {
            "explanation": self._extract_section(response_text, "explanation"),
            "fixed_code": self._extract_code_block(response_text),
            "reasoning": self._extract_section(response_text, "reasoning"),
            "confidence": 7,  # Default confidence
            "additional_notes": self._extract_section(response_text, "additional")
        }

    def _extract_section(self, text: str, section: str) -> str:
        """Extract specific sections from AI response"""
        patterns = [
            rf"{section}[:\s]*(.+?)(?=\n\s*\w+:|$)",
            rf"{section.upper()}[:\s]*(.+?)(?=\n\s*\w+:|$)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
        
        return "Not available"

    def _extract_code_block(self, text: str) -> str:
        """Extract code blocks from AI response"""
        code_patterns = [
            r'```lua\s*(.+?)```',
            r'```\s*(.+?)```',
            r'FIXED?_?CODE[:\s]*```\s*(.+?)```'
        ]
        
        for pattern in code_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
        
        return "No fixed code provided"

class InteractiveChatAgent:
    """Interactive chat agent for security questions and analysis"""
    
    def __init__(self):
        """Initialize the Chat Agent"""
        self.api_key = os.getenv('AGENT_API_KEY')
        if not self.api_key:
            raise ValueError("AGENT_API_KEY not found in environment variables")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        self.conversation_history = []

    def chat(self, user_message: str, code_context: str = None) -> Dict:
        """
        Handle interactive chat about security topics
        
        Args:
            user_message: User's question or message
            code_context: Optional code for context
            
        Returns:
            Dictionary with agent response and metadata
        """
        
        # Build context-aware prompt
        prompt = self._build_chat_prompt(user_message, code_context)
        
        try:
            response = self.model.generate_content(prompt)
            
            # Store conversation
            self.conversation_history.append({
                "user": user_message,
                "agent": response.text,
                "timestamp": "2025-07-09"
            })
            
            return {
                "response": response.text,
                "conversation_id": len(self.conversation_history),
                "has_code_context": code_context is not None
            }
            
        except Exception as e:
            return {
                "response": f"I'm having trouble processing your request: {str(e)}",
                "error": True
            }

    def _build_chat_prompt(self, message: str, code: str = None) -> str:
        """Build chat prompt with context"""
        
        base_prompt = """
        You are a security expert assistant specializing in Lua smart contract security.
        You help developers understand vulnerabilities, best practices, and secure coding patterns.
        
        Format your responses clearly and professionally:
        - Use markdown formatting for better readability
        - Structure your responses with headers (## or ###)
        - Use bullet points or numbered lists where appropriate
        - Highlight important concepts with **bold text**
        - Use `code snippets` when referencing code
        - Use code blocks with ```lua for larger code examples
        - Keep explanations clear and educational
        - Focus on practical, actionable advice
        - When explaining vulnerabilities, include:
          1. What the vulnerability is
          2. Why it's dangerous
          3. How to fix it
          4. Best practices to prevent it
        
        Example response format:
        ## Understanding [Topic]
        
        **What it is:**
        [Brief explanation]
        
        **Why it's dangerous:**
        - [Risk 1]
        - [Risk 2]
        
        **How to fix:**
        ```lua
        -- Secure code example
        ```
        
        **Best practices:**
        1. [Practice 1]
        2. [Practice 2]
        """
        
        if code:
            base_prompt += f"""
            
            **CODE CONTEXT PROVIDED:**
            ```lua
            {code}
            ```
            
            Consider this code when providing your response. If relevant, analyze it for security issues.
            """
        
        base_prompt += f"""
        
        **USER QUESTION:** {message}
        
        Please provide a helpful, well-formatted response following the guidelines above.
        """
        
        return base_prompt

# Factory function for easy agent creation
def create_security_agent() -> SecurityAgent:
    """Create and return a SecurityAgent instance"""
    return SecurityAgent()

def create_chat_agent() -> InteractiveChatAgent:
    """Create and return an InteractiveChatAgent instance"""
    return InteractiveChatAgent()
