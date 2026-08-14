use api_tester_domain::{HttpFlow, HttpMethod};
use api_tester_query::HTTPQLParser;
use proptest::prelude::*;

fn atom() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("method:GET".to_owned()),
        Just("method:POST".to_owned()),
        Just("resp.status:>=400".to_owned()),
        Just("resp.status:200".to_owned()),
        Just("path:/api/*".to_owned()),
        Just("req.body:error".to_owned()),
        Just("resp.body:token".to_owned()),
    ]
}

fn make_flow(method: HttpMethod, path: &str, status: u16, body: Option<&str>) -> HttpFlow {
    let mut flow = HttpFlow::new(method, "api.example.com", path);
    flow.full_url = format!("https://api.example.com{path}");
    flow.response_status = status;
    flow.response_body = body.map(str::to_owned);
    flow
}

// Arbitrary (possibly invalid) input must never panic the parser.
proptest! {
    #[test]
    fn parse_never_panics(query in "[ -~]{0,40}") {
        let _ = HTTPQLParser.parse(&query);
    }

    #[test]
    fn parse_nested_expressions_ok(
        atoms in prop::collection::vec(atom(), 2..5),
        operator in prop::sample::select(&["|", "&"]),
        depth in 0..3usize,
    ) {
        let mut inner = atoms.join(operator);
        for _ in 0..depth {
            inner = format!("({inner})");
        }
        prop_assert!(HTTPQLParser.parse(&inner).is_ok());
    }

    #[test]
    fn parsed_conditions_never_panic(
        atoms in prop::collection::vec(atom(), 1..4),
        operator in prop::sample::select(&["|", "&"]),
    ) {
        let query = atoms.join(operator);
        let Ok(condition) = HTTPQLParser.parse(&query) else {
            return Ok(());
        };
        let flows = [
            make_flow(HttpMethod::Get, "/api/users", 500, Some("error")),
            make_flow(HttpMethod::Post, "/api/login", 200, Some("token=abc")),
            make_flow(HttpMethod::Delete, "/other", 401, None),
        ];
        for flow in &flows {
            let _ = condition.matches(flow);
        }
    }
}

#[test]
fn nested_expression_semantics() {
    let condition = HTTPQLParser
        .parse("(method:GET | method:POST) & resp.status:>=400")
        .unwrap();
    assert!(condition.matches(&make_flow(HttpMethod::Post, "/api/login", 500, None)));
    assert!(!condition.matches(&make_flow(HttpMethod::Get, "/api/login", 200, None)));
    assert!(!condition.matches(&make_flow(HttpMethod::Delete, "/api/login", 500, None)));
}

#[test]
fn invalid_inputs_are_typed_errors() {
    for query in [
        "method",
        "bogus:value",
        "(method:GET",
        "(method:GET | method:POST",
        "resp.status:>=abc",
    ] {
        let parsed = HTTPQLParser.parse(query);
        assert!(parsed.is_err(), "expected error for {query:?}");
    }
}
