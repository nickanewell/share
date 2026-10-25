use std::{collections::hash_map::RandomState, hash::BuildHasher, sync::Arc};
use tokio::sync::{Mutex, MutexGuard};

const LOCK_SHARDS: usize = 1024;

#[derive(Clone, Default)]
pub struct SharedState {
    pub locks: Arc<NoteLocks>,
}

pub struct NoteLocks {
    shards: [Mutex<()>; LOCK_SHARDS],
    hash_builder: RandomState,
}

impl Default for NoteLocks {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(())),
            hash_builder: RandomState::new(),
        }
    }
}

impl NoteLocks {
    fn shard_index(&self, id: &str) -> usize {
        (self.hash_builder.hash_one(id) % LOCK_SHARDS as u64) as usize
    }

    pub async fn lock(&self, id: &str) -> MutexGuard<'_, ()> {
        // Untrusted IDs must not allocate permanent locks. Collisions deliberately
        // serialize unrelated notes; a process-local random hash limits targeting.
        self.shards[self.shard_index(id)].lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::{LOCK_SHARDS, NoteLocks, SharedState};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{sync::Barrier, task::JoinSet};

    #[tokio::test]
    async fn unique_ids_do_not_grow_lock_storage() {
        let locks = NoteLocks::default();
        let original_storage = locks.shards.as_ptr();
        let original_size = std::mem::size_of_val(&locks);

        for id in 0..100_000 {
            let _guard = locks.lock(&format!("missing-note-{id}")).await;
        }

        assert_eq!(locks.shards.len(), LOCK_SHARDS);
        assert_eq!(locks.shards.as_ptr(), original_storage);
        assert_eq!(std::mem::size_of_val(&locks), original_size);
    }

    async fn assert_serialized(state: &SharedState, ids: &[String]) {
        const TASKS: usize = 16;
        const ITERATIONS: usize = 32;
        let barrier = Arc::new(Barrier::new(TASKS));
        let active = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();

        for task in 0..TASKS {
            let state = state.clone();
            let id = ids[task % ids.len()].clone();
            let barrier = barrier.clone();
            let active = active.clone();
            let completed = completed.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                for _ in 0..ITERATIONS {
                    let _guard = state.locks.lock(&id).await;
                    assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                    // Force overlapping attempts while the critical section is held.
                    tokio::task::yield_now().await;
                    completed.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                }
            });
        }

        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(completed.load(Ordering::SeqCst), TASKS * ITERATIONS);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_note_is_serialized_across_state_clones() {
        let state = SharedState::default();
        for round in 0..4 {
            assert_serialized(&state, &[format!("shared-note-{round}")]).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn colliding_note_ids_are_also_serialized() {
        let state = SharedState::default();
        let mut seen: [Option<String>; LOCK_SHARDS] = std::array::from_fn(|_| None);
        let mut collision = None;
        // Pigeonhole principle guarantees a collision without relying on a fixed seed.
        for index in 0..=LOCK_SHARDS {
            let id = format!("collision-note-{index}");
            let shard = state.locks.shard_index(&id);
            if let Some(previous) = &seen[shard] {
                collision = Some([previous.clone(), id]);
                break;
            }
            seen[shard] = Some(id);
        }

        let ids = collision.expect("more note IDs than shards must collide");
        assert_ne!(ids[0], ids[1]);
        assert_serialized(&state, &ids).await;
    }

    #[tokio::test]
    async fn different_shards_progress_independently() {
        let locks = NoteLocks::default();
        let first_id = "held-note";
        let first_shard = locks.shard_index(first_id);
        let other_id = (0..100_000)
            .map(|id| format!("other-note-{id}"))
            .find(|id| locks.shard_index(id) != first_shard)
            .expect("random hashing should distribute IDs across multiple shards");

        let _first_guard = locks.lock(first_id).await;
        let _other_guard = tokio::time::timeout(Duration::from_secs(1), locks.lock(&other_id))
            .await
            .expect("an unrelated shard must stay available while a note is locked");
    }
}
