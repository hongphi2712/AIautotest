use api_tester_domain::HttpFlow;

use crate::condition::Condition;

pub struct QueryExecutor;

impl QueryExecutor {
    pub fn execute(&self, flows: &[HttpFlow], condition: &Condition) -> Vec<HttpFlow> {
        flows
            .iter()
            .filter(|flow| condition.matches(flow))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::QueryExecutor;
    use crate::dsl::Q;
    use api_tester_domain::{HttpFlow, HttpMethod};

    fn make_flow(method: HttpMethod, path: &str) -> HttpFlow {
        let mut flow = HttpFlow::new(method, "api.example.com", path);
        flow.full_url = format!("https://api.example.com{path}");
        flow.response_status = 200;
        flow
    }

    #[test]
    fn execute_filters() {
        let flows = vec![
            make_flow(HttpMethod::Get, "/api/a"),
            make_flow(HttpMethod::Post, "/api/b"),
            make_flow(HttpMethod::Get, "/api/c"),
        ];
        let executor = QueryExecutor;
        let condition = Q::method().eq("GET");
        let result = executor.execute(&flows, &condition);

        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|flow| flow.method == HttpMethod::Get));
    }
}
