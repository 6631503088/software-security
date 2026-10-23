# Threat Model — Week 1 Sample App

## 1. Data-flow diagram
(Insert your DFD image. Mark trust boundaries with dashed lines.)
![Task 1 DFD](img/task1-dfd.jpg)

## 2. Elements & trust boundaries
| Element | Type (process/store/entity/flow) | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet → app) |
| Flask app | process | yes (receives requests across Internet → app) |
| SQLite DB (`notes.db`) | data store | no (same trusted server zone) |
| `uploads/` store | data store | no (same trusted server zone) |

## 3. STRIDE analysis
| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| /notes | Yes | No | Yes | Yes | No | No |
| /upload | No| Yes | Yes | Yes | Yes | No |
| /files/<name> | No | No | Yes | Yes | No | No |

## 4. Top 5 risks (likelihood × impact) + mitigation
1.
2.
3.
4.
5.
