use std::collections::VecDeque;
use std::sync::RwLock;

pub struct RingBuffer<T> {
    data: RwLock<VecDeque<T>>,
    capacity: usize,
}

impl<T> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "RingBuffer capacity must be positive");
        Self {
            data: RwLock::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn push(&self, item: T) {
        let mut data = self
            .data
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        if data.len() >= self.capacity {
            data.pop_front();
        }
        data.push_back(item);
    }

    pub fn len(&self) -> usize {
        self.data
            .read()
            .map(|data| data.len())
            .unwrap_or_else(|poison| poison.into_inner().len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes every buffered item. Used by the UI's "Clear log" action.
    pub fn clear(&self) {
        self.data
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }
}

impl<T: Clone> RingBuffer<T> {
    pub fn snapshot(&self) -> Vec<T> {
        let data = self
            .data
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        data.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::RingBuffer;

    #[test]
    fn snapshot_returns_consistent_copy() {
        let buffer = RingBuffer::new(3);
        buffer.push(1);
        buffer.push(2);
        buffer.push(3);
        buffer.push(4);

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.snapshot(), vec![2, 3, 4]);
    }

    #[test]
    fn clear_empties_the_buffer() {
        let buffer = RingBuffer::new(3);
        buffer.push(1);
        buffer.push(2);

        buffer.clear();

        assert_eq!(buffer.len(), 0);
        assert!(buffer.snapshot().is_empty());
    }
}
