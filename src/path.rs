pub(crate) fn path_match_score(pattern: &str, request_path: &str) -> Option<usize> {
    if pattern == request_path {
        return Some(1_000_000 + pattern.len());
    }
    if pattern != "/"
        && !pattern.ends_with('/')
        && request_path
            .strip_suffix('/')
            .is_some_and(|request_path| request_path == pattern)
    {
        return Some(999_000 + pattern.len());
    }

    if pattern == "/*" {
        return Some(1);
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        if let Some(score) = trailing_wildcard_match_score(prefix, request_path) {
            return Some(score);
        }
    }

    segment_wildcard_match_score(pattern, request_path)
}

fn trailing_wildcard_match_score(prefix: &str, request_path: &str) -> Option<usize> {
    let prefix = prefix.trim_end_matches('/');
    if request_path != prefix
        && !request_path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
    {
        return None;
    }

    let literal_chars = path_literal_chars(prefix);
    Some(wildcard_score(literal_chars, literal_chars))
}

fn segment_wildcard_match_score(pattern: &str, request_path: &str) -> Option<usize> {
    let pattern_segments = split_path_segments(pattern);
    let wildcard_index = pattern_segments
        .iter()
        .position(|segment| *segment == "*")?;
    let request_segments = split_path_segments(request_path);
    if pattern_segments.len() != request_segments.len() {
        return None;
    }

    let mut total_literal_chars = 0;
    for (pattern_segment, request_segment) in pattern_segments.iter().zip(request_segments) {
        if *pattern_segment == "*" {
            continue;
        }
        if pattern_segment.contains('*') {
            return None;
        }
        if *pattern_segment != request_segment {
            return None;
        }
        total_literal_chars += pattern_segment.len();
    }

    let leading_literal_chars = pattern_segments
        .iter()
        .take(wildcard_index)
        .map(|segment| segment.len())
        .sum();
    Some(wildcard_score(leading_literal_chars, total_literal_chars))
}

fn wildcard_score(leading_literal_chars: usize, total_literal_chars: usize) -> usize {
    100 + leading_literal_chars * 1_000 + total_literal_chars
}

fn path_literal_chars(path: &str) -> usize {
    split_path_segments(path)
        .into_iter()
        .map(|segment| segment.len())
        .sum()
}

fn split_path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}
