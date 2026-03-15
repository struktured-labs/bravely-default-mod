# Autobattle DSL Schema

## Overview

The autobattle system uses a concise DSL (Domain-Specific Language) to define
conditional battle rules. Rules are single-line strings in the format:

```
conditions → actions
```

Rules are grouped into named **profiles**, and profiles are assigned to
character slots (0-3). During battle, each character's assigned profile is
evaluated top-to-bottom; the first rule whose conditions all match fires its
action list.

## YAML Structure

```yaml
profiles:
  ProfileName:
    - "conditions → actions"
    - "→ fallback actions"

assignments: [ProfileName, ProfileName, ProfileName, ProfileName]
activeProfile: ProfileName
```

- **profiles**: Dictionary of profile name to list of DSL rule strings.
- **assignments**: Ordered list of 4 profile names (one per party slot).
- **activeProfile**: The default profile (used when a slot has no assignment).

## DSL Syntax

### Arrow

Use any of: `→` (Unicode), `->`, `=>`

### Conditions (left of arrow)

- Empty (nothing before arrow) = **Always** (unconditional)
- Multiple conditions joined with `&` (AND logic)
- Format: `STAT OP VALUE[%]`

| Stat       | Meaning                | Value Type   | Example          |
|------------|------------------------|-------------|------------------|
| `HP`       | Character HP percent   | Number + %  | `HP < 30%`       |
| `MP`       | Character MP percent   | Number + %  | `MP > 10%`       |
| `BP`       | Current brave points   | Integer     | `BP > 2`         |
| `Foes`     | Alive enemy count      | Integer     | `Foes = 1`       |
| `Allies`   | Alive ally count       | Integer     | `Allies < 3`     |
| `Turn`     | Current turn number    | Integer     | `Turn = 1`       |

Operators: `<`, `<=`, `=`, `>=`, `>`, `!=`

### Actions (right of arrow)

- Comma-separated list of actions
- `xN` suffix repeats that action N times
- Format: `TYPE [PARAMS] [TARGET]`

| Action          | Meaning                          | Example           |
|-----------------|----------------------------------|--------------------|
| `Atk Weak`      | Attack weakest enemy             | `Atk Weak x4`     |
| `Atk Strong`    | Attack strongest enemy (max HP)  | `Atk Strong x2`   |
| `Atk Random`    | Attack random enemy              | `Atk Random`      |
| `Cure Self`     | Cure ability on self (ability 1) | `Cure Self`        |
| `Cure Ally`     | Cure weakest ally (ability 1)    | `Cure Ally`        |
| `Abl N Self`    | Use ability ID N on self         | `Abl 5 Self`       |
| `Abl N Ally`    | Use ability ID N on weakest ally | `Abl 3 Ally`       |
| `Abl N Foe`     | Use ability ID N on weakest foe  | `Abl 7 Foe`        |
| `Item N Self`   | Use item ID N on self            | `Item 1 Self`      |
| `Item N Ally`   | Use item ID N on weakest ally    | `Item 2 Ally`      |
| `Guard`         | Defend this turn                 | `Guard`            |
| `Default`       | Use game's built-in action       | `Default`          |

### Target Words

| Word                         | Resolves To       |
|------------------------------|-------------------|
| `Self` / `Me`               | Self              |
| `Ally` / `Allies` / `Friend`| Weakest ally      |
| `Foe` / `Enemy` / `Weak`    | Weakest enemy     |
| `Strong` / `Strongest`      | Strongest enemy   |
| `Random` / `Rnd`            | Random enemy      |

## Full Example

```yaml
profiles:
  Attack 4x:
    - "→ Atk Weak x4"

  Healer:
    - "HP < 30% → Cure Self"
    - "→ Atk Weak"

  Boss Fight:
    - "HP < 50% → Cure Ally, Atk Strong x2"
    - "Foes = 1 → Atk Strong x4"
    - "→ Atk Weak x3"

  Nuke:
    - "BP > 2 & HP > 50% → Atk Strong x4"
    - "→ Atk Weak"

  Default: []

assignments: [Attack 4x, Attack 4x, Healer, Attack 4x]
activeProfile: Attack 4x
```

### How It Evaluates

For each character each turn:
1. Look up the character's assigned profile (or activeProfile as fallback).
2. Walk the rule list top-to-bottom.
3. For the first rule where ALL conditions are true, execute ALL its actions.
4. If no rule matches, fall back to the game's original autobattle behavior.

### Multi-Action (Brave)

A single rule can emit multiple actions. The engine submits one
AddAttackCommand per action in the list. For example, `Atk Strong x4` sends
four attack commands, using 3 BP (brave three times).

### Notes

- Ability and Item actions are not yet fully implemented at the native command
  level. They currently fall back to attack.
- The `Turn` condition requires turn-number tracking, which defaults to 1
  until wired to the game's turn counter.
- Empty profile (`Default: []`) means "no rules" — falls back to original
  game autobattle.
