\# NOVA AI - Testing Report



\## Objective



To verify that all modules of NOVA AI function correctly and produce expected results.



\---



\# Test Cases



| Test ID | Module | Expected Result | Status |

|----------|--------|-----------------|--------|

| TC-01 | Safe Email Detection | HAM | PASS |

| TC-02 | Spam Email Detection | SPAM | PASS |

| TC-03 | Phishing Detection | Detect phishing indicators | PASS |

| TC-04 | Security Analysis | Detect spam keywords | PASS |

| TC-05 | Sender Analysis | Detect suspicious sender | PASS |

| TC-06 | Risk Engine | Calculate final score | PASS |

| TC-07 | Scan History | Save and display history | PASS |

| TC-08 | Report Generation | Generate latest report | PASS |

| TC-09 | Statistics | Display correct statistics | PASS |



\---



\# Test Email 1



Sender:

```

professor@college.edu

```



Expected:



```

HAM

```



Result:



```

PASS

```



\---



\# Test Email 2



Sender:



```

winner@free-prize.com

```



Expected:



```

SPAM

```



Result:



```

PASS

```



\---



\# Performance



Dataset



```

Spam Messages : 747



Ham Messages : 4827

```



Training completed successfully.



\---



\# Conclusion



All modules were tested successfully.



The application correctly identifies spam and legitimate emails while generating reports, maintaining history, and calculating statistics.

