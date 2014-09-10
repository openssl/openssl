#pragma once

namespace winrtcomponent
{
  public delegate void testUpdated(Platform::Object^ sender, Platform::String^ runName, int errorcode, double interval);
    public ref class testClass sealed
    {
    public:
      event testUpdated^ testExecuted;
        testClass()
        {
        }
        void updateRun(Platform::String ^runName, int errorcode, double interval)
        {
          testExecuted(this, runName, errorcode, interval);
        }
        int test();
    };
}