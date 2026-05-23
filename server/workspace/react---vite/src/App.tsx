import { useState } from 'react'

function App() {
  const [count, setCount] = useState(0)

  return (
    <div style={{ padding: '2rem', fontFamily: 'system-ui' }}>
      <h1>react---vite</h1>
      <button onClick={() => setCount(c => c + 1)}>Count: {count}</button>
    </div>
  )
}

export default App
