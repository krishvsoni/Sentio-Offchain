# ------------------------------------------------------------------------------
# Learning Agent Module for Lua Security Analyzer
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
from typing import Dict, List, Optional
import numpy as np
from collections import defaultdict

class VulnerabilityPattern:
    """Represents a learned vulnerability pattern"""
    
    def __init__(self, code_snippet: str, vulnerability_type: str, 
                 confidence: float, metadata: Dict = None):
        self.code_snippet = code_snippet
        self.vulnerability_type = vulnerability_type
        self.confidence = confidence
        self.metadata = metadata or {}
        self.hash = self._generate_hash()
        self.created_at = datetime.now().isoformat()
        self.usage_count = 0
        
    def _generate_hash(self) -> str:
        """Generate unique hash for the pattern"""
        content = f"{self.code_snippet}{self.vulnerability_type}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def to_dict(self) -> Dict:
        """Convert pattern to dictionary for storage"""
        return {
            "code_snippet": self.code_snippet,
            "vulnerability_type": self.vulnerability_type,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "hash": self.hash,
            "created_at": self.created_at,
            "usage_count": self.usage_count
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
        return pattern

class LearningAgent:
    """AI Learning Agent that improves vulnerability detection over time"""
    
    def __init__(self, patterns_file: str = "learned_patterns.json"):
        self.patterns_file = patterns_file
        self.patterns: List[VulnerabilityPattern] = []
        self.pattern_stats = defaultdict(int)
        self.feedback_history = []
        self.load_patterns()
    
    def load_patterns(self):
        """Load learned patterns from file"""
        if os.path.exists(self.patterns_file):
            try:
                with open(self.patterns_file, 'r') as f:
                    data = json.load(f)
                    self.patterns = [VulnerabilityPattern.from_dict(p) for p in data.get("patterns", [])]
                    self.pattern_stats = defaultdict(int, data.get("stats", {}))
                    self.feedback_history = data.get("feedback_history", [])
                    print(f"Loaded {len(self.patterns)} learned patterns")
            except Exception as e:
                print(f"Error loading patterns: {e}")
                self.patterns = []
    
    def save_patterns(self):
        """Save learned patterns to file"""
        try:
            data = {
                "patterns": [p.to_dict() for p in self.patterns],
                "stats": dict(self.pattern_stats),
                "feedback_history": self.feedback_history,
                "last_updated": datetime.now().isoformat(),
                "total_patterns": len(self.patterns)
            }
            with open(self.patterns_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"Saved {len(self.patterns)} patterns to {self.patterns_file}")
        except Exception as e:
            print(f"Error saving patterns: {e}")
    
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
        """Check code against learned patterns"""
        matches = []
        
        for pattern in self.patterns:
            similarity = self._calculate_similarity(pattern.code_snippet, code_snippet)
            
            if similarity > 0.6:  # Threshold for pattern match
                confidence = pattern.confidence * similarity
                
                match = {
                    "vulnerability_type": pattern.vulnerability_type,
                    "confidence": confidence,
                    "similarity": similarity,
                    "learned_pattern": True,
                    "pattern_metadata": pattern.metadata,
                    "usage_count": pattern.usage_count
                }
                matches.append(match)
                
                # Update usage count
                pattern.usage_count += 1
        
        # Sort by confidence
        matches.sort(key=lambda x: x["confidence"], reverse=True)
        return matches
    
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
        """Get statistics about learned patterns"""
        return {
            "total_patterns": len(self.patterns),
            "patterns_by_type": dict(self.pattern_stats),
            "feedback_entries": len(self.feedback_history),
            "average_confidence": np.mean([p.confidence for p in self.patterns]) if self.patterns else 0,
            "most_common_vulnerabilities": sorted(
                self.pattern_stats.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]
        }
    
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

# Factory function
def create_learning_agent() -> LearningAgent:
    """Create and return a LearningAgent instance"""
    return LearningAgent()
