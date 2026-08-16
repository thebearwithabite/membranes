# ElevenLabs v3 — Audio Tags Reference

ElevenLabs v3 does **not** support SSML. It uses natural-language **audio tags**
in square brackets instead. These are more flexible than SSML — write what you
want the voice to do, and the model interprets it.

Audio tags are exclusive to `eleven_v3`. Other ElevenLabs models ignore them.

---

## Tag syntax

Place tags in `[square brackets]` anywhere in the text. Tags apply to the
speech that follows them until the next tag or end of text.

```
[excited] I can't believe we actually did it! [pause] [softly] But at what cost?
```

---

## Tag categories

### Emotional states

`[excited]` `[nervous]` `[frustrated]` `[sorrowful]` `[calm]` `[angry]`
`[joyful]` `[fearful]` `[disgusted]` `[surprised]` `[melancholy]`
`[content]` `[anxious]` `[hopeful]` `[resigned]`

### Reactions and sound effects

`[sigh]` `[sighs]` `[laughs]` `[chuckles]` `[gulps]` `[gasps]`
`[clears throat]` `[sniffles]` `[groans]`

### Delivery / volume

`[whispers]` `[whispering]` `[shouts]` `[shouting]` `[speaking softly]`
`[muttering]` `[yelling]`

### Tone cues

`[cheerfully]` `[flatly]` `[deadpan]` `[playfully]` `[sarcastically]`
`[warmly]` `[coldly]` `[gravely]` `[tenderly]` `[menacingly]`

### Emphasis

`[emphasized]` `[stress on next word]` `[understated]`

### Pacing and rhythm

`[pause]` `[short pause]` `[long pause]` `[rushed]` `[slowly]`
`[stammers]` `[hesitates]` `[drawn out]`

### Cognitive beats

`[pauses]` `[hesitates]` `[stammers]` `[resigned tone]`
`[trails off]` `[thinking]`

### Multi-character dialogue

`[overlapping]` `[cuts in]` `[interrupting]`

---

## Punctuation prosody (v3-enhanced)

Standard punctuation carries extra weight in v3:

| Punctuation | Effect in v3 |
|---|---|
| `...` | Natural pause, trailing off |
| `—` | Abrupt interruption |
| ALL CAPS | Emphasis on word |
| `!` | Increased energy |
| `?!` | Surprised exclamation |

---

## Example scripts

### Narration with emotional arc

```
[calm] The forest was quiet that morning.
[pause]
[nervous] But something felt wrong.
[whispers] The trees themselves seemed to be watching.
[gasps]
[shouting] Run!
```

### Dialogue with delivery cues

```
[cheerfully] Hey! Long time no see!
[pause]
[hesitates] I, uh... I wasn't sure you'd come.
[softly] I missed you.
```

### Podcast / voiceover

```
[warmly] Welcome back to the show, everyone.
[pause]
[excited] Today we've got an incredible topic.
[emphasized] And trust me — you don't want to miss this.
```

---

## Tips

- Tags are free-form natural language — experiment beyond the listed examples
- Don't over-tag; v3 naturally varies prosody from context
- Use punctuation and sentence structure alongside tags for best results
- Combine emotion + delivery: `[nervous] [whispering] Is someone there?`
- For pronunciation control, use PLS dictionaries (see the `elevenlabs` skill)
- Request stitching is **not** available with v3 — use `eleven_multilingual_v2`
  for multi-chunk prosody continuity
