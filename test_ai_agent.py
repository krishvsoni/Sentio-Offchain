#!/usr/bin/env python3
"""
Test script for AI Agent Enhanced Lua Security Analyzer
Tests basic functionality of AI agent features
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"

# Test vulnerable Lua code
TEST_CODE = """
-- Vulnerable Lua smart contract example
local balance = 1000000000
local amount = 2147483647

-- Integer overflow vulnerability
local new_balance = balance + amount

-- Reentrancy vulnerability
function transfer(to, value)
    if balance >= value then
        call_external(to, value)  -- External call before state change
        balance = balance - value
    end
end

-- Missing access control
function emergency_withdraw()
    send_all_funds(owner)
end

-- Private key exposure
local private_key = "0x1234567890abcdef"
"""

def test_traditional_analysis():
    """Test traditional vulnerability analysis"""
    print("🔍 Testing Traditional Analysis...")
    
    try:
        response = requests.post(f"{BASE_URL}/analyze", 
                               data={'code': TEST_CODE})
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Found {len(data.get('vulnerabilities', []))} vulnerabilities")
            print(f"   Total lines: {data.get('total_lines', 0)}")
            print(f"   Vulnerable lines: {data.get('vulnerable_lines', 0)}")
            return True
        else:
            print(f"❌ Traditional analysis failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Traditional analysis error: {e}")
        return False

def test_ai_analysis():
    """Test AI-enhanced analysis"""
    print("🤖 Testing AI Enhanced Analysis...")
    
    try:
        response = requests.post(f"{BASE_URL}/ai/analyze", 
                               json={'code': TEST_CODE})
        
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            print(f"✅ AI found {len(vulns)} vulnerabilities")
            
            # Check for AI enhancements
            ai_enhanced = sum(1 for v in vulns if v.get('ai_fix'))
            print(f"   AI-enhanced vulnerabilities: {ai_enhanced}")
            
            if data.get('ai_analysis'):
                print("   ✅ AI overall analysis included")
            
            return True
        else:
            print(f"❌ AI analysis failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ AI analysis error: {e}")
        return False

def test_ai_chat():
    """Test AI chat functionality"""
    print("💬 Testing AI Chat...")
    
    try:
        test_message = "What is reentrancy and why is it dangerous?"
        response = requests.post(f"{BASE_URL}/ai/chat", 
                               json={'message': test_message})
        
        if response.status_code == 200:
            data = response.json()
            if data.get('response'):
                print("✅ AI chat working")
                print(f"   Response length: {len(data['response'])} characters")
                return True
            else:
                print("❌ AI chat returned empty response")
                return False
        else:
            print(f"❌ AI chat failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ AI chat error: {e}")
        return False

def test_learning_agent():
    """Test learning agent functionality"""
    print("🧠 Testing Learning Agent...")
    
    try:
        # Get learning stats
        response = requests.get(f"{BASE_URL}/learning/stats")
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('stats', {})
            print(f"✅ Learning agent working")
            print(f"   Total patterns: {stats.get('total_patterns', 0)}")
            print(f"   Suggestions: {len(data.get('suggestions', []))}")
            
            # Test training
            train_response = requests.post(f"{BASE_URL}/learning/train",
                json={
                    'code_snippet': 'local x = 2147483647 + 1',
                    'vulnerability': {
                        'name': 'Integer Overflow',
                        'description': 'Potential integer overflow',
                        'severity': 'high'
                    },
                    'user_feedback': 'Test pattern'
                })
            
            if train_response.status_code == 200:
                print("   ✅ Learning agent training works")
                return True
            else:
                print(f"   ❌ Learning training failed: {train_response.status_code}")
                return False
        else:
            print(f"❌ Learning stats failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Learning agent error: {e}")
        return False

def test_server_health():
    """Test if server is running"""
    print("🏥 Testing Server Health...")
    
    try:
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code == 200:
            print("✅ Server is running")
            return True
        else:
            print(f"❌ Server returned: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Is it running?")
        return False
    except Exception as e:
        print(f"❌ Server health check error: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 AI Agent Test Suite")
    print("=" * 50)
    
    tests = [
        ("Server Health", test_server_health),
        ("Traditional Analysis", test_traditional_analysis),
        ("AI Enhanced Analysis", test_ai_analysis),
        ("AI Chat", test_ai_chat),
        ("Learning Agent", test_learning_agent),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        success = test_func()
        results.append((test_name, success))
        
        if not success and test_name == "Server Health":
            print("\n❌ Server not running. Please start the server first:")
            print("   python app.py")
            break
    
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    
    passed = 0
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"   {test_name}: {status}")
        if success:
            passed += 1
    
    print(f"\nPassed: {passed}/{len(results)} tests")
    
    if passed == len(results):
        print("🎉 All tests passed! AI Agent is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    main()
