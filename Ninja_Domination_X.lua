-- Ninja Domination X GUI by ChatGPT 💀
-- BRUTAL Ninja Legends Script (All-in-One GUI)
-- Compatible with: KRNL, Fluxus, Synapse X

-- UI Library (Kavo Simple UI)
local Library = loadstring(game:HttpGet("https://pastebin.com/raw/LyH2zZ6A"))()
local Window = Library:CreateWindow("Ninja Domination X")

local autoSwing = false
local autoSell = false
local autoBuy = false
local unlockIsland = false
local autoChi = false
local autoRebirth = false

local Tab = Window:CreateTab("Main", true)

Tab:CreateToggle("Auto Swing", function(v) autoSwing = v end)
Tab:CreateToggle("Auto Sell", function(v) autoSell = v end)
Tab:CreateToggle("Auto Buy Gear", function(v) autoBuy = v end)
Tab:CreateToggle("Unlock All Islands", function(v) unlockIsland = v end)
Tab:CreateToggle("Auto Collect Chi", function(v) autoChi = v end)
Tab:CreateToggle("Auto Rank Up", function(v) autoRebirth = v end)

Tab:CreateButton("Teleport Next Island", function()
    game:GetService("ReplicatedStorage").Remotes.TeleportIsland:FireServer("Next")
end)

-- Anti-AFK
game:GetService("Players").LocalPlayer.Idled:Connect(function()
    game:GetService("VirtualInputManager"):SendKeyEvent(true, "Space", false, game)
end)

-- Main Loop
spawn(function()
    while true do
        pcall(function()
            local player = game.Players.LocalPlayer
            local rs = game:GetService("ReplicatedStorage")
            if autoSwing then
                for _, tool in pairs(player.Backpack:GetChildren()) do
                    if tool:IsA("Tool") and tool:FindFirstChild("Swing") then
                        tool:Activate()
                    end
                end
            end
            if autoSell then
                rs.Remotes.Sell:FireServer()
            end
            if autoBuy then
                rs.Remotes.BuyAllSwords:FireServer("Ground")
                rs.Remotes.BuyAllRanks:FireServer("Ground")
            end
            if unlockIsland then
                rs.Remotes.UnlockIsland:FireServer("All")
            end
            if autoChi then
                for _, v in pairs(workspace:GetDescendants()) do
                    if v.Name:match("ChiOrb") and v:IsA("Part") then
                        v.CFrame = player.Character.HumanoidRootPart.CFrame
                    end
                end
            end
            if autoRebirth then
                rs.Remotes.BuyRank:FireServer("Best")
            end
        end)
        wait(0.2)
    end
end)

print("✅ Ninja Domination X GUI loaded")
