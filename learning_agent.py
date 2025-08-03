# ------------------------------------------------------------------------------
# Sentio Arena
# Project: Offchain Analyzer - Learning Agent
# Author: Sentio Team
# Email: connectsentio@gmail.com
# Date Published: 2025-07-9
# Description: Learning agent that improves over time by storing and analyzing
#              vulnerability patterns for enhanced detection.
# ------------------------------------------------------------------------------

import json
import os
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
import numpy as np
from collections import defaultdict
import re

class VulnerabilityPattern:
    """Represents a learned vulnerability pattern with enhanced metadata"""
    
    def __init__(self, code_snippet: str, vulnerability_type: str, 
                 confidence: float, metadata: Dict = None):
        self.code_snippet = code_snippet
        self.vulnerability_type = vulnerability_type
        self.confidence = confidence
        self.metadata = metadata or {}
        self.hash = self._generate_hash()
        self.created_at = datetime.now().isoformat()
        self.usage_count = 0
        self.accuracy_score = 0.0  
        self.false_positive_count = 0
        self.true_positive_count = 0
        
    def _generate_hash(self) -> str:
        """Generate unique hash for the pattern"""
        content = f"{self.code_snippet}{self.vulnerability_type}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def update_accuracy(self, is_correct: bool):
        """Update accuracy metrics based on feedback"""
        if is_correct:
            self.true_positive_count += 1
        else:
            self.false_positive_count += 1
        
        total_predictions = self.true_positive_count + self.false_positive_count
        if total_predictions > 0:
            self.accuracy_score = self.true_positive_count / total_predictions
    
    def get_severity_weight(self) -> float:
        """Get weight based on severity level"""
        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.4
        }
        severity = self.metadata.get("severity", "medium").lower()
        return severity_weights.get(severity, 0.6)
    
    def extract_keywords(self) -> Set[str]:
        """Extract keywords from code snippet for better matching"""
        keywords = set()
        
        # Add detection keywords from metadata
        if "detection_keywords" in self.metadata:
            keywords.update(self.metadata["detection_keywords"])
        
        # Extract function names, variable names, operators
        code_lower = self.code_snippet.lower()
        
        # Function patterns
        func_patterns = re.findall(r'function\s+(\w+)', code_lower)
        keywords.update(func_patterns)
        
        # Variable patterns
        var_patterns = re.findall(r'local\s+(\w+)', code_lower)
        keywords.update(var_patterns)
        
        # Common vulnerability indicators
        vuln_indicators = [
            'overflow', 'underflow', 'external_call', 'reentrancy',
            'private_key', 'secret', 'balance', 'transfer', 'mint', 'burn',
            'admin', 'owner', 'access', 'control', 'replay', 'reset'
        ]
        
        for indicator in vuln_indicators:
            if indicator in code_lower:
                keywords.add(indicator)
        
        return keywords
    
    def to_dict(self) -> Dict:
        """Convert pattern to dictionary for storage"""
        return {
            "code_snippet": self.code_snippet,
            "vulnerability_type": self.vulnerability_type,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "hash": self.hash,
            "created_at": self.created_at,
            "usage_count": self.usage_count,
            "accuracy_score": self.accuracy_score,
            "false_positive_count": self.false_positive_count,
            "true_positive_count": self.true_positive_count
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'VulnerabilityPattern':
        """Create pattern from dictionary"""
        pattern = cls(
            data["code_snippet"],
            data["vulnerability_type"],
            data["confidence"],
            data.get("metadata", {})
        )
        pattern.hash = data.get("hash", pattern.hash)
        pattern.created_at = data.get("created_at", pattern.created_at)
        pattern.usage_count = data.get("usage_count", 0)
        pattern.accuracy_score = data.get("accuracy_score", 0.0)
        pattern.false_positive_count = data.get("false_positive_count", 0)
        pattern.true_positive_count = data.get("true_positive_count", 0)
        return pattern

class LearningAgent:
    """Enhanced AI Learning Agent that improves vulnerability detection over time"""
    
    def __init__(self, patterns_file: str = "learned_patterns.json"):
        self.patterns_file = patterns_file
        self.patterns: List[VulnerabilityPattern] = []
        self.pattern_stats = defaultdict(int)
        self.feedback_history = []
        self.vulnerability_weights = defaultdict(float)  # Dynamic weights per vulnerability type
        self.learning_threshold = 0.7  # Minimum confidence for auto-learning
        self.pattern_cache = {}  # Cache for faster pattern matching
        self.load_patterns()
        self._update_vulnerability_weights()
    
    def load_patterns(self):
        """Load learned patterns from file"""
        if os.path.exists(self.patterns_file):
            try:
                with open(self.patterns_file, 'r') as f:
                    data = json.load(f)
                    self.patterns = [VulnerabilityPattern.from_dict(p) for p in data.get("patterns", [])]
                    self.pattern_stats = defaultdict(int, data.get("stats", {}))
                    self.feedback_history = data.get("feedback_history", [])
                    print(f"✅ Loaded {len(self.patterns)} learned patterns from {self.patterns_file}")
            except Exception as e:
                print(f"❌ Error loading patterns: {e}")
                self.patterns = []
        else:
            print(f"📝 No existing patterns file found. Starting fresh.")
    
    def save_patterns(self):
        """Save learned patterns to file"""
        try:
            data = {
                "patterns": [p.to_dict() for p in self.patterns],
                "stats": dict(self.pattern_stats),
                "feedback_history": self.feedback_history[-100:],  # Keep last 100 feedback entries
                "vulnerability_weights": dict(self.vulnerability_weights),
                "last_updated": datetime.now().isoformat(),
                "total_patterns": len(self.patterns),
                "learning_metadata": {
                    "learning_threshold": self.learning_threshold,
                    "average_accuracy": self._calculate_average_accuracy(),
                    "top_vulnerabilities": self._get_top_vulnerabilities(5)
                }
            }
            with open(self.patterns_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"💾 Saved {len(self.patterns)} patterns to {self.patterns_file}")
        except Exception as e:
            print(f"❌ Error saving patterns: {e}")
    
    def _update_vulnerability_weights(self):
        """Update dynamic weights based on pattern performance"""
        for pattern in self.patterns:
            vuln_type = pattern.vulnerability_type
            # Weight based on accuracy and severity
            accuracy_weight = pattern.accuracy_score if pattern.accuracy_score > 0 else 0.5
            severity_weight = pattern.get_severity_weight()
            usage_weight = min(pattern.usage_count / 10.0, 1.0)  # Cap at 1.0
            
            combined_weight = (accuracy_weight * 0.4 + severity_weight * 0.4 + usage_weight * 0.2)
            self.vulnerability_weights[vuln_type] = max(
                self.vulnerability_weights[vuln_type], 
                combined_weight
            )
    
    def _calculate_average_accuracy(self) -> float:
        """Calculate average accuracy across all patterns"""
        if not self.patterns:
            return 0.0
        
        total_score = sum(p.accuracy_score for p in self.patterns)
        return total_score / len(self.patterns)
    
    def _get_top_vulnerabilities(self, limit: int) -> List[Tuple[str, int]]:
        """Get top vulnerability types by frequency"""
        return sorted(self.pattern_stats.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def learn_from_vulnerability(self, code_snippet: str, vulnerability: Dict, 
                                user_feedback: str = None) -> bool:
        """Learn a new pattern from detected vulnerability"""
        try:
            # Extract relevant information
            vuln_type = vulnerability.get("name", "Unknown")
            severity = vulnerability.get("severity", "medium")
            
            # Calculate confidence based on severity and existing patterns
            base_confidence = self._calculate_base_confidence(severity)
            
            # Check if similar pattern already exists
            existing_pattern = self._find_similar_pattern(code_snippet, vuln_type)
            
            if existing_pattern:
                # Update existing pattern
                existing_pattern.confidence = min(1.0, existing_pattern.confidence + 0.1)
                existing_pattern.usage_count += 1
                return False
            else:
                # Create new pattern
                metadata = {
                    "severity": severity,
                    "description": vulnerability.get("description", ""),
                    "pattern": vulnerability.get("pattern", ""),
                    "line": vulnerability.get("line"),
                    "user_feedback": user_feedback
                }
                
                new_pattern = VulnerabilityPattern(
                    code_snippet, vuln_type, base_confidence, metadata
                )
                
                self.patterns.append(new_pattern)
                self.pattern_stats[vuln_type] += 1
                
                print(f"Learned new pattern for {vuln_type}")
                return True
                
        except Exception as e:
            print(f"Error learning from vulnerability: {e}")
            return False
    
    def _calculate_base_confidence(self, severity: str) -> float:
        """Calculate base confidence score based on severity"""
        severity_weights = {
            "high": 0.9,
            "medium": 0.7,
            "low": 0.5
        }
        return severity_weights.get(severity.lower(), 0.6)
    
    def _find_similar_pattern(self, code_snippet: str, vuln_type: str) -> Optional[VulnerabilityPattern]:
        """Find similar existing pattern"""
        # Simple similarity check - could be enhanced with fuzzy matching
        for pattern in self.patterns:
            if (pattern.vulnerability_type == vuln_type and 
                self._calculate_similarity(pattern.code_snippet, code_snippet) > 0.8):
                return pattern
        return None
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate simple text similarity"""
        # Remove whitespace and normalize
        t1 = ''.join(text1.split()).lower()
        t2 = ''.join(text2.split()).lower()
        
        if not t1 or not t2:
            return 0.0
        
        # Calculate Jaccard similarity with character n-grams
        n = 3
        ngrams1 = set(t1[i:i+n] for i in range(len(t1)-n+1))
        ngrams2 = set(t2[i:i+n] for i in range(len(t2)-n+1))
        
        if not ngrams1 and not ngrams2:
            return 1.0
        if not ngrams1 or not ngrams2:
            return 0.0
            
        intersection = len(ngrams1.intersection(ngrams2))
        union = len(ngrams1.union(ngrams2))
        
        return intersection / union if union > 0 else 0.0
    
    def check_against_learned_patterns(self, code_snippet: str) -> List[Dict]:
        """Check code against learned patterns with enhanced matching"""
        matches = []
        snippet_keywords = set(self._extract_keywords_from_snippet(code_snippet))
        
        for pattern in self.patterns:
            # Calculate multiple similarity metrics
            text_similarity = self._calculate_similarity(pattern.code_snippet, code_snippet)
            keyword_similarity = self._calculate_keyword_similarity(pattern, code_snippet)
            
            # Weighted similarity calculation
            combined_similarity = (text_similarity * 0.7 + keyword_similarity * 0.3)
            
            # Dynamic threshold based on pattern accuracy and vulnerability weight
            vuln_weight = self.vulnerability_weights.get(pattern.vulnerability_type, 0.5)
            threshold = max(0.6 - (vuln_weight * 0.1), 0.4)  # Lower threshold for important vulnerabilities
            
            if combined_similarity > threshold:
                # Calculate confidence with multiple factors
                base_confidence = pattern.confidence * combined_similarity
                accuracy_boost = pattern.accuracy_score * 0.2
                usage_boost = min(pattern.usage_count / 20.0, 0.1)  # Small boost for frequently used patterns
                
                final_confidence = min(base_confidence + accuracy_boost + usage_boost, 1.0)
                
                match = {
                    "vulnerability_type": pattern.vulnerability_type,
                    "confidence": final_confidence,
                    "text_similarity": text_similarity,
                    "keyword_similarity": keyword_similarity,
                    "combined_similarity": combined_similarity,
                    "learned_pattern": True,
                    "pattern_metadata": pattern.metadata,
                    "usage_count": pattern.usage_count,
                    "accuracy_score": pattern.accuracy_score,
                    "severity": pattern.metadata.get("severity", "medium"),
                    "keywords_matched": list(snippet_keywords.intersection(set(pattern.get_keywords()))),
                    "pattern_age_days": self._calculate_pattern_age(pattern),
                    "vulnerability_weight": vuln_weight
                }
                matches.append(match)
                
                # Update usage count and recalculate weights
                pattern.usage_count += 1
        
        # Sort by confidence (higher is better)
        matches.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Update vulnerability weights after pattern matching
        self._update_vulnerability_weights()
        
        return matches
    
    def _calculate_pattern_age(self, pattern: VulnerabilityPattern) -> int:
        """Calculate how many days old a pattern is"""
        try:
            created_date = datetime.fromisoformat(pattern.created_at.replace('Z', '+00:00'))
            age = (datetime.now() - created_date).days
            return age
        except:
            return 0
    
    def record_feedback(self, vulnerability_id: str, feedback: str, 
                       is_correct: bool, user_comment: str = None):
        """Record user feedback for learning improvement"""
        feedback_entry = {
            "vulnerability_id": vulnerability_id,
            "feedback": feedback,
            "is_correct": is_correct,
            "user_comment": user_comment,
            "timestamp": datetime.now().isoformat()
        }
        
        self.feedback_history.append(feedback_entry)
        
        # Limit feedback history size
        if len(self.feedback_history) > 1000:
            self.feedback_history = self.feedback_history[-800:]
    
    def get_learning_stats(self) -> Dict:
        """Get comprehensive statistics about learned patterns"""
        if not self.patterns:
            return {
                "total_patterns": 0,
                "patterns_by_type": {},
                "feedback_entries": len(self.feedback_history),
                "average_confidence": 0,
                "average_accuracy": 0,
                "most_common_vulnerabilities": [],
                "learning_insights": ["No patterns learned yet. Start analyzing code to build intelligence."]
            }
        
        # Calculate comprehensive statistics
        total_accuracy = sum(p.accuracy_score for p in self.patterns)
        total_confidence = sum(p.confidence for p in self.patterns)
        total_usage = sum(p.usage_count for p in self.patterns)
        
        # Vulnerability type analysis
        vulnerability_analysis = {}
        for pattern in self.patterns:
            vtype = pattern.vulnerability_type
            if vtype not in vulnerability_analysis:
                vulnerability_analysis[vtype] = {
                    "count": 0,
                    "avg_accuracy": 0,
                    "avg_confidence": 0,
                    "total_usage": 0,
                    "severity_distribution": defaultdict(int)
                }
            
            vuln_data = vulnerability_analysis[vtype]
            vuln_data["count"] += 1
            vuln_data["avg_accuracy"] += pattern.accuracy_score
            vuln_data["avg_confidence"] += pattern.confidence
            vuln_data["total_usage"] += pattern.usage_count
            
            severity = pattern.metadata.get("severity", "medium")
            vuln_data["severity_distribution"][severity] += 1
        
        # Finalize averages
        for vtype, data in vulnerability_analysis.items():
            count = data["count"]
            data["avg_accuracy"] /= count
            data["avg_confidence"] /= count
        
        # Generate learning insights
        insights = self._generate_learning_insights(vulnerability_analysis)
        
        # Top performing patterns
        top_patterns = sorted(
            self.patterns, 
            key=lambda p: (p.accuracy_score * 0.6 + p.confidence * 0.4), 
            reverse=True
        )[:5]
        
        return {
            "total_patterns": len(self.patterns),
            "patterns_by_type": dict(self.pattern_stats),
            "feedback_entries": len(self.feedback_history),
            "average_confidence": total_confidence / len(self.patterns),
            "average_accuracy": total_accuracy / len(self.patterns),
            "total_usage_count": total_usage,
            "vulnerability_analysis": vulnerability_analysis,
            "most_common_vulnerabilities": sorted(
                self.pattern_stats.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5],
            "top_performing_patterns": [
                {
                    "type": p.vulnerability_type,
                    "accuracy": p.accuracy_score,
                    "confidence": p.confidence,
                    "usage": p.usage_count
                } for p in top_patterns
            ],
            "vulnerability_weights": dict(self.vulnerability_weights),
            "cache_stats": {
                "cached_patterns": len(self.pattern_cache),
                "cache_hit_rate": self._calculate_cache_hit_rate()
            },
            "learning_insights": insights,
            "learning_metadata": {
                "learning_threshold": self.learning_threshold,
                "pattern_file": self.patterns_file,
                "last_updated": datetime.now().isoformat()
            }
        }
    
    def _generate_learning_insights(self, vulnerability_analysis: Dict) -> List[str]:
        """Generate actionable insights from learning data"""
        insights = []
        
        # Accuracy insights
        low_accuracy_types = [
            vtype for vtype, data in vulnerability_analysis.items() 
            if data["avg_accuracy"] < 0.6
        ]
        if low_accuracy_types:
            insights.append(f"🔍 Low accuracy detected for: {', '.join(low_accuracy_types)}. Consider reviewing these patterns.")
        
        # Usage insights
        unused_patterns = [
            vtype for vtype, data in vulnerability_analysis.items() 
            if data["total_usage"] < 2
        ]
        if unused_patterns:
            insights.append(f"📊 Rarely used patterns: {', '.join(unused_patterns)}. May need more diverse training data.")
        
        # Severity insights
        high_severity_count = sum(
            1 for data in vulnerability_analysis.values() 
            if data["severity_distribution"].get("high", 0) > 0
        )
        if high_severity_count > len(vulnerability_analysis) * 0.3:
            insights.append("⚠️ High proportion of critical vulnerabilities detected. Review security practices.")
        
        # Learning progress insights
        total_patterns = len(self.patterns)
        if total_patterns < 10:
            insights.append("🌱 Early learning stage. Need more code samples to improve accuracy.")
        elif total_patterns < 50:
            insights.append("📈 Good learning progress. Continue feeding diverse code samples.")
        else:
            insights.append("🎯 Mature learning model. Focus on pattern refinement and accuracy.")
        
        return insights
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate (placeholder - would need actual tracking)"""
        # This would require actual cache hit/miss tracking in a real implementation
        return min(len(self.pattern_cache) / max(len(self.patterns), 1), 1.0)
    
    def suggest_improvements(self) -> List[str]:
        """Suggest improvements based on learned patterns"""
        suggestions = []
        
        stats = self.get_learning_stats()
        
        if stats["total_patterns"] < 10:
            suggestions.append("Need more training data. Consider running more code samples.")
        
        if stats["average_confidence"] < 0.7:
            suggestions.append("Pattern confidence is low. Consider providing more feedback.")
        
        low_confidence_types = [
            vuln_type for vuln_type, count in stats["patterns_by_type"].items() 
            if count < 3
        ]
        
        if low_confidence_types:
            suggestions.append(f"Need more examples for: {', '.join(low_confidence_types)}")
        
        return suggestions
    
    def export_patterns(self, export_file: str = None) -> str:
        """Export patterns for sharing or backup"""
        export_file = export_file or f"patterns_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "total_patterns": len(self.patterns),
            "patterns": [p.to_dict() for p in self.patterns],
            "statistics": self.get_learning_stats()
        }
        
        with open(export_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        return export_file
    
    def import_patterns(self, import_file: str) -> int:
        """Import patterns from file"""
        try:
            with open(import_file, 'r') as f:
                data = json.load(f)
            
            imported_patterns = data.get("patterns", [])
            imported_count = 0
            
            for pattern_data in imported_patterns:
                pattern = VulnerabilityPattern.from_dict(pattern_data)
                
                # Check if pattern already exists
                existing = self._find_similar_pattern(
                    pattern.code_snippet, 
                    pattern.vulnerability_type
                )
                
                if not existing:
                    self.patterns.append(pattern)
                    self.pattern_stats[pattern.vulnerability_type] += 1
                    imported_count += 1
            
            print(f"Imported {imported_count} new patterns")
            return imported_count
            
        except Exception as e:
            print(f"Error importing patterns: {e}")
            return 0
    
    def add_pattern(self, vulnerability_type: str, code_snippet: str, context: dict, 
                   confidence: float = 0.8, severity: str = "medium", ai_feedback: str = None):
        """Add a new learned pattern with enhanced metadata"""
        # Check if similar pattern already exists
        existing_pattern = self.find_similar_pattern(code_snippet, vulnerability_type)
        
        if existing_pattern:
            # Update existing pattern with new information
            existing_pattern.usage_count += 1
            existing_pattern.confidence = max(existing_pattern.confidence, confidence)
            
            # Update accuracy based on successful detection
            if ai_feedback and "correct" in ai_feedback.lower():
                existing_pattern.accuracy_score = min(existing_pattern.accuracy_score + 0.1, 1.0)
                existing_pattern.true_positive_count += 1
            elif ai_feedback and "incorrect" in ai_feedback.lower():
                existing_pattern.false_positive_count += 1
                existing_pattern.accuracy_score = max(existing_pattern.accuracy_score - 0.05, 0.0)
            
            # Merge context information
            if context:
                existing_pattern.metadata.update(context)
                
            print(f"🔄 Updated existing pattern for {vulnerability_type}")
            self.save_patterns()
            return existing_pattern
        else:
            # Create new pattern with enhanced metadata
            metadata = context or {}
            metadata.update({
                "severity": severity,
                "ai_feedback": ai_feedback or "",
                "keywords": self._extract_keywords_from_snippet(code_snippet),
                "created_at": datetime.now().isoformat()
            })
            
            new_pattern = VulnerabilityPattern(
                code_snippet, 
                vulnerability_type, 
                confidence, 
                metadata
            )
            
            # Initialize accuracy with confidence score
            new_pattern.accuracy_score = confidence
            new_pattern.usage_count = 1
            
            self.patterns.append(new_pattern)
            self.pattern_stats[vulnerability_type] += 1
            
            print(f"✅ Added new pattern for {vulnerability_type} (confidence: {confidence})")
            self.save_patterns()
            return new_pattern
    
    def _extract_keywords_from_snippet(self, code_snippet: str) -> List[str]:
        """Extract meaningful keywords from code snippet"""
        # Common Lua keywords and patterns to extract
        lua_keywords = {'function', 'local', 'if', 'then', 'else', 'for', 'while', 'do', 'end',
                       'return', 'break', 'repeat', 'until', 'and', 'or', 'not', 'in'}
        
        # Security-related keywords
        security_keywords = {'eval', 'exec', 'system', 'os.execute', 'io.popen', 'loadstring',
                           'dofile', 'require', 'module', 'debug', 'getmetatable', 'setmetatable',
                           'rawget', 'rawset', 'tonumber', 'tostring', 'pcall', 'xpcall',
                           'pairs', 'ipairs', 'next', 'select', 'unpack', 'table.insert',
                           'table.remove', 'string.gsub', 'string.match', 'io.open', 'io.read',
                           'math.random', 'math.randomseed', 'collectgarbage'}
        
        words = re.findall(r'\b\w+\b', code_snippet.lower())
        keywords = []
        
        for word in words:
            if word in security_keywords:
                keywords.append(word)
            elif len(word) > 3 and word not in lua_keywords:  # Meaningful identifiers
                keywords.append(word)
        
        return list(set(keywords))  # Remove duplicates
    
    def find_similar_pattern(self, code_snippet: str, vulnerability_type: str) -> Optional[VulnerabilityPattern]:
        """Find similar existing pattern with enhanced matching"""
        cache_key = f"{vulnerability_type}:{hash(code_snippet)}"
        
        if cache_key in self.pattern_cache:
            return self.pattern_cache[cache_key]
        
        best_match = None
        best_similarity = 0.0
        
        for pattern in self.patterns:
            if pattern.vulnerability_type == vulnerability_type:
                # Calculate multiple similarity metrics
                text_similarity = self._calculate_similarity(pattern.code_snippet, code_snippet)
                keyword_similarity = self._calculate_keyword_similarity(pattern, code_snippet)
                
                # Weighted combination of similarities
                combined_similarity = (text_similarity * 0.7 + keyword_similarity * 0.3)
                
                if combined_similarity > best_similarity and combined_similarity > 0.75:
                    best_similarity = combined_similarity
                    best_match = pattern
        
        # Cache the result
        self.pattern_cache[cache_key] = best_match
        return best_match
    
    def _calculate_keyword_similarity(self, pattern: VulnerabilityPattern, code_snippet: str) -> float:
        """Calculate similarity based on extracted keywords"""
        pattern_keywords = set(pattern.get_keywords())
        snippet_keywords = set(self._extract_keywords_from_snippet(code_snippet))
        
        if not pattern_keywords and not snippet_keywords:
            return 1.0
        if not pattern_keywords or not snippet_keywords:
            return 0.0
        
        intersection = len(pattern_keywords.intersection(snippet_keywords))
        union = len(pattern_keywords.union(snippet_keywords))
        
        return intersection / union if union > 0 else 0.0

# Factory function
def create_learning_agent() -> LearningAgent:
    """Create and return a LearningAgent instance"""
    return LearningAgent()
