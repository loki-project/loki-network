#include <path/path_buffers.hpp>

namespace llarp
{
  namespace path
  {
    struct MemPool_Impl
    {
      template<typename Pool_t>
      struct PoolHolder
      {
        Pool_t m_Pool;
        size_t m_Uses = 0;

        void 
        IncRef()
        {
          m_Uses ++;
        }

        bool
        DecRef()
        {
          if(m_Uses)
          {
            m_Uses--;
          }
          return Done();
        }

        bool 
        Done() const
        {
          return m_Uses == 0;
        }

        bool 
        CanHoldMore() const
        {
          return m_Uses < 32;
        }

        using Ptr_t = PoolHolder *;

      };

      using UpstreamHolder_t = PoolHolder<UpstreamBufferPool_t>;
      using DownstreamHolder_t = PoolHolder<DownstreamBufferPool_t>;
      
      std::list<UpstreamHolder_t> m_Upstream;
      std::list<DownstreamHolder_t> m_Downstream;

      template<typename T>
      static T *
      Obtain(std::list<PoolHolder<T> > & l) 
      {
        for(auto & holder : l)
        {
          if(holder.CanHoldMore())
          {
            holder.IncRef();
            return &holder.m_Pool;
          }
        }
        const auto idx = l.size();
        l.emplace_back();
        auto & h = l.back();
        h.m_Pool.Index = idx;
        h.IncRef();
        return &h.m_Pool;
      }

      template<typename T> 
      static void
      Return(std::list<PoolHolder< T> > & l, T * pool)
      {
        assert(pool != nullptr);
        auto itr = l.begin();
        for(size_t idx = 0; idx < pool->Index; itr ++) {};
        if(itr->DecRef())
        {
          itr->m_Pool.Finish();
          l.erase(itr);
          // reindex pools
          size_t idx = 0;
          itr = l.begin();
          while(itr != l.end())
          {
            itr->m_Pool.Index = idx;
            ++idx;
            ++itr;
          }
        }
      }

      DownstreamBufferPool_t::Ptr_t
      ObtainDownstreamBufferPool()
      {
        return Obtain(m_Downstream);
      }

      void
      ReturnDownstreamBufferPool(DownstreamBufferPool_t::Ptr_t pool)
      {
        Return(m_Downstream, pool);
      }

      UpstreamBufferPool_t::Ptr_t
      ObtainUpstreamBufferPool()
      {
        return Obtain(m_Upstream);
      }

      void
      ReturnUpstreamBufferPool(UpstreamBufferPool_t::Ptr_t pool)
      {
        Return(m_Upstream, pool);
      }

    };

    MemPool::MemPool() : m_Impl(new MemPool_Impl()) {}
    MemPool::~MemPool() { delete m_Impl; }

    UpstreamBufferPool_t::Ptr_t
    MemPool::ObtainUpstreamBufferPool()
    {
      return m_Impl->ObtainUpstreamBufferPool();
    }

    void 
    MemPool::ReturnUpstreamBufferPool(UpstreamBufferPool_t::Ptr_t p)
    {
      m_Impl->ReturnUpstreamBufferPool(p);
    }

    DownstreamBufferPool_t::Ptr_t
    MemPool::ObtainDownstreamBufferPool()
    {
      return m_Impl->ObtainDownstreamBufferPool();
    }

    void 
    MemPool::ReturnDownstreamBufferPool(DownstreamBufferPool_t::Ptr_t p)
    {
      m_Impl->ReturnDownstreamBufferPool(p);
    }

    

  }
}