package org.ghoncha.app

/**
 * Assigns monotonically increasing generations to network identities.
 *
 * A generation changes whenever an active network's routing-relevant state
 * changes. Socket factories capture a generation and must reject work once it
 * is no longer current.
 */
internal class NetworkGenerationRegistry<K> {
    private val generations = HashMap<K, Long>()
    private var nextGeneration = 1L

    @Synchronized
    fun activate(key: K): Long = assign(key)

    @Synchronized
    fun advance(key: K): Long? {
        if (key !in generations) return null
        return assign(key)
    }

    @Synchronized
    fun current(key: K): Long? = generations[key]

    @Synchronized
    fun deactivate(key: K): Long? = generations.remove(key)

    @Synchronized
    fun clear() {
        generations.clear()
    }

    private fun assign(key: K): Long {
        check(nextGeneration > 0 && nextGeneration < Long.MAX_VALUE) {
            "Network generation space exhausted"
        }
        val generation = nextGeneration++
        generations[key] = generation
        return generation
    }
}
